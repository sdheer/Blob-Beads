"""
server.py — MCP tool handlers for mcp-temporal-vault.

Tool registration follows the MCP SDK single-dispatch pattern:
  - @app.list_tools()  declares all tools so clients can discover them.
  - @app.call_tool()   routes all tool calls through a single dispatcher.

All tool responses are serialised with json.dumps() — never with f-string
JSON construction — to prevent malformed output when inputs contain quotes
or braces.
"""

import json
import logging
import mimetypes
import os
import time
import uuid
import hashlib
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Sequence

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from mcp_temporal_vault.audit import audit
from mcp_temporal_vault.beads import (
    BeadStorageError,
    append_bead,
    find_bead,
    get_last_bead,
    iter_beads_reverse,
)
from mcp_temporal_vault.cas import CASStorageError, read_blob, store_blob_staged, commit_staging, clear_staging
from mcp_temporal_vault.crypto import sign_manifest, verify_manifest
from mcp_temporal_vault.git_bridge import (
    cwd_inside_git_repo,
    find_git_root,
    get_head_sha,
    git_checkout_detach,
    is_clean_worktree,
    tracked_paths_at_commit,
)
from mcp_temporal_vault.key_manager import get_vault_key
from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.models import (
    Bead,
    CheckoutStateInput,
    GetSummaryDeltaInput,
    ManifestEntry,
    SaveStateInput,
    SquashMilestoneInput,
)
from mcp_temporal_vault.quota import gc_collect as run_gc_collect
from mcp_temporal_vault.security import (
    SecurityError,
    assert_safe_path,
    fingerprint_hybrid,
    is_ignored,
    scan_for_injection,
)
from mcp_temporal_vault.squash import SquashError, squash_milestone_range

logger = logging.getLogger(__name__)

app = Server("temporal-vault")

_ACTIVE_SAVE_TASK = None
_CANCEL_EVENT = asyncio.Event()

class SaveCancelledError(Exception):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(payload: Any) -> List[TextContent]:
    return [TextContent(type="text", text=json.dumps(payload))]


def _err(code: str, message: str, detail: Any = None) -> List[TextContent]:
    body: Dict[str, Any] = {"code": code, "message": message}
    if detail is not None:
        body["detail"] = detail
    return [TextContent(type="text", text=json.dumps({"error": body}))]


def _get_mime_type(path: str) -> str:
    mime_type, _ = mimetypes.guess_type(path)
    return mime_type or "application/octet-stream"


def _is_in_vault(file_path: Path) -> bool:
    """Returns True if file_path lives inside the vault directory.
    Prevents vault metadata files from being snapshotted into manifests."""
    try:
        file_path.resolve().relative_to(global_config.vault_dir.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Tool declarations — required so MCP clients can discover available tools
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> List[Tool]:
    return [
        Tool(
            name="save_state",
            description=(
                "Captures the current reasoning step as a Bead (JSONL) and "
                "pushes all new file-content Blobs to the hashbucket CAS store."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "maxLength": 128},
                    "summary":    {"type": "string", "maxLength": 4096},
                    "step_type":  {"type": "string", "enum": ["checkpoint", "decision", "observation", "todo_update"]},
                    "decisions":  {"type": "array", "items": {"type": "string"}},
                    "todos":      {"type": "array", "items": {"type": "string"}},
                },
                "required": ["project_id", "summary"],
            },
        ),
        Tool(
            name="list_states",
            description=(
                "Lists Bead headers for a project (or all projects) in reverse "
                "chronological order. No blob content is read."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {"type": ["string", "null"]},
                },
            },
        ),
        Tool(
            name="checkout_state",
            description=(
                "Restores the working directory to the exact filesystem state "
                "recorded in the given Bead. DESTRUCTIVE."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "bead_id": {"type": "string"},
                    "force":   {"type": "boolean", "default": False},
                },
                "required": ["bead_id"],
            },
        ),
        Tool(
            name="get_summary_delta",
            description=(
                "Returns the semantic and structural delta between two Beads. "
                "No files are read from or written to the filesystem."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "bead_a": {"type": "string"},
                    "bead_b": {"type": "string"},
                },
                "required": ["bead_a", "bead_b"],
            },
        ),
        Tool(
            name="squash_milestone",
            description=(
                "Replace an inclusive chronological span of beads with one milestone bead "
                "(merged decisions/todos, manifest from tip). Optionally trim CAS manifest "
                "entries reproducible from git at bead.git_sha and run GC."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {"type": "string", "maxLength": 128},
                    "first_bead_id": {"type": "string"},
                    "last_bead_id": {"type": "string"},
                    "milestone_summary": {"type": "string", "maxLength": 8192},
                    "prune_git_blobs": {"type": "boolean", "default": False},
                    "step_type": {
                        "type": "string",
                        "enum": ["checkpoint", "decision", "observation", "todo_update", "milestone"],
                        "default": "milestone",
                    },
                },
                "required": [
                    "project_id",
                    "first_bead_id",
                    "last_bead_id",
                    "milestone_summary",
                ],
            },
        ),
        Tool(
            name="gc_collect",
            description=(
                "Delete hashbucket blobs not referenced by any bead manifest across "
                "all projects."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


# ---------------------------------------------------------------------------
# Single call_tool dispatcher — the MCP SDK routes ALL tool calls here
# ---------------------------------------------------------------------------

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> List[TextContent]:
    try:
        key = get_vault_key()
    except Exception as exc:
        audit("KEY_ERROR", {"error": str(exc)})
        return _err("KEY_ERROR", str(exc))

    if key is None:
        audit("KEY_MISSING_ON_START")
        return _err(
            "MISSING_ENCRYPTION_KEY",
            "Encryption key not configured. Create ~/.mcp_vault/key "
            "(chmod 600) or set MCP_VAULT_KEY env var.",
        )
    if name == "save_state":
        return await _save_state(arguments)
    if name == "list_states":
        return await _list_states(arguments)
    if name == "checkout_state":
        return await _checkout_state(arguments)
    if name == "get_summary_delta":
        return await _get_summary_delta(arguments)
    if name == "squash_milestone":
        return await _squash_milestone(arguments)
    if name == "gc_collect":
        return await _gc_collect(arguments)
    return _err("UNKNOWN_TOOL", f"No tool named '{name}'")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

async def _background_save_task(inp: SaveStateInput, cwd: Path, ignore_patterns: List[str]):
    global _ACTIVE_SAVE_TASK
    manifest: Dict[str, ManifestEntry] = {}
    staged_files = []
    try:
        for root, dirs, files in os.walk(cwd):
            if _CANCEL_EVENT.is_set():
                raise SaveCancelledError("Save cancelled by checkout")
                
            # Prune ignored directories and vault dir in-place
            dirs[:] = [
                d for d in dirs
                if not is_ignored(
                    (Path(root) / d).relative_to(cwd).as_posix() + "/",
                    ignore_patterns,
                ) and not _is_in_vault(Path(root) / d)
            ]
            for file in files:
                if _CANCEL_EVENT.is_set():
                    raise SaveCancelledError("Save cancelled by checkout")
                    
                file_path = Path(root) / file
                rel_path = file_path.relative_to(cwd).as_posix()
                if is_ignored(rel_path, ignore_patterns):
                    continue
                if _is_in_vault(file_path):
                    continue
                if not file_path.is_file():
                    continue
                stat = file_path.stat()
                if stat.st_size > global_config.max_file_size_mb * 1024 * 1024:
                    continue

                def process_file(fp: Path, pid: str) -> tuple[str, Path]:
                    with open(fp, "rb") as f:
                        raw_bytes = f.read()
                    staged_path = store_blob_staged(raw_bytes, project_id=pid)
                    return hashlib.sha256(raw_bytes).hexdigest(), staged_path

                sha256, staged_path = await asyncio.to_thread(process_file, file_path, inp.project_id)
                if staged_path and staged_path.name:
                    staged_files.append(staged_path)
                    
                mime_type = _get_mime_type(file_path.as_posix())
                manifest[rel_path] = ManifestEntry(
                    sha256=sha256, 
                    mime_type=mime_type, 
                    size=stat.st_size
                )
                
        if _CANCEL_EVENT.is_set():
            raise SaveCancelledError("Save cancelled by checkout")

        last_bead = await asyncio.to_thread(get_last_bead, inp.project_id)
        bead_id = str(uuid.uuid4())

        resolved_cwd = cwd.resolve()
        repo_root = find_git_root(resolved_cwd)
        git_sha_val = None
        if (
            repo_root is not None
            and cwd_inside_git_repo(resolved_cwd, repo_root)
            and is_clean_worktree(repo_root)
        ):
            git_sha_val = get_head_sha(repo_root)

        key = get_vault_key()
        signature = (
            await asyncio.to_thread(sign_manifest, manifest, key, git_sha_val) if key else None
        )

        new_bead = Bead(
            bead_id=bead_id,
            project_id=inp.project_id,
            parent_id=last_bead.bead_id if last_bead else None,
            timestamp=int(time.time()),
            step_type=inp.step_type,
            summary=inp.summary,
            decisions=inp.decisions,
            todos=inp.todos,
            manifest=manifest,
            manifest_signature=signature,
            git_sha=git_sha_val,
        )

        await asyncio.to_thread(commit_staging, staged_files)
        await asyncio.to_thread(append_bead, new_bead)
        
        logger.info(f"Background save completed successfully. Bead ID: {bead_id}")
        audit("SAVE_COMPLETED", {"bead_id": bead_id})

    except SaveCancelledError:
        logger.info("Background save cancelled.")
        audit("SAVE_CANCELLED", {"project_id": inp.project_id})
        await asyncio.to_thread(clear_staging)
    except Exception as exc:
        logger.error(f"Background save failed: {exc}")
        audit("SAVE_FAILED", {"error": str(exc)})
        await asyncio.to_thread(clear_staging)
    finally:
        _ACTIVE_SAVE_TASK = None
        _CANCEL_EVENT.clear()


async def _save_state(arguments: dict) -> List[TextContent]:
    global _ACTIVE_SAVE_TASK
    try:
        inp = SaveStateInput.model_validate(arguments)
    except Exception as exc:
        return _err("INVALID_INPUT", str(exc))

    if _ACTIVE_SAVE_TASK is not None and not _ACTIVE_SAVE_TASK.done():
        return _err("SAVE_IN_PROGRESS", "A background save is already in progress. Wait for it to finish or perform a checkout to cancel it.")

    cwd = Path(os.getcwd())
    ignore_patterns = global_config.get_project_ignore_patterns(cwd)

    _CANCEL_EVENT.clear()
    _ACTIVE_SAVE_TASK = asyncio.create_task(_background_save_task(inp, cwd, ignore_patterns))

    return _ok({
        "status": "pending",
        "message": "Snapshot creation started in background. Check server logs for bead_id upon completion."
    })


async def _list_states(arguments: dict) -> List[TextContent]:
    project_id = arguments.get("project_id")

    if project_id:
        gen = iter_beads_reverse(project_id)
    else:
        def _all_beads():
            for p in global_config.get_beads_dir().glob("*.jsonl"):
                yield from iter_beads_reverse(p.stem)
        gen = _all_beads()

    beads_list = []
    for i, bead in enumerate(gen):
        if i >= 200:
            break
        row = {
            "bead_id":    bead.bead_id,
            "parent_id":  bead.parent_id,
            "timestamp":  bead.timestamp,
            "step_type":  bead.step_type,
            "summary":    bead.summary,
            "file_count": len(bead.manifest),
        }
        if bead.git_sha:
            row["git_sha"] = bead.git_sha
        beads_list.append(row)

    beads_list.sort(key=lambda x: x["timestamp"], reverse=True)
    return _ok(beads_list)


async def _checkout_state(arguments: dict) -> List[TextContent]:
    global _ACTIVE_SAVE_TASK
    
    warning_msg = None
    if _ACTIVE_SAVE_TASK is not None and not _ACTIVE_SAVE_TASK.done():
        _CANCEL_EVENT.set()
        await _ACTIVE_SAVE_TASK
        warning_msg = "Restore successful. Note: Background save for the previous unsaved state was cancelled to prevent data collision."

    try:
        inp = CheckoutStateInput.model_validate(arguments)
    except Exception as exc:
        return _err("INVALID_INPUT", str(exc))

    target_bead = find_bead(inp.bead_id)
    if not target_bead:
        return _err("BEAD_NOT_FOUND", f"No bead with id '{inp.bead_id}'")

    key = get_vault_key()
    if target_bead.manifest_signature and key:
        if not verify_manifest(
            target_bead.manifest,
            target_bead.manifest_signature,
            key,
            target_bead.git_sha,
        ):
            audit("MANIFEST_TAMPERED", {"bead_id": target_bead.bead_id})
            return _err("MANIFEST_TAMPERED", "Bead manifest signature verification failed")

    cwd = Path(os.getcwd())
    resolved_cwd = cwd.resolve()
    repo_root = find_git_root(resolved_cwd)
    git_repo_ctx = (
        repo_root
        if repo_root is not None and cwd_inside_git_repo(resolved_cwd, repo_root)
        else None
    )
    hybrid_root = git_repo_ctx if target_bead.git_sha else None

    if not inp.force and fingerprint_hybrid(cwd, target_bead, hybrid_root):
        return _err(
            "DIRTY_WORKING_DIR",
            "Untracked changes detected. Save first or pass force=true.",
        )

    paths_expected = set(target_bead.manifest.keys())
    if target_bead.git_sha and git_repo_ctx is not None:
        paths_expected |= tracked_paths_at_commit(git_repo_ctx, target_bead.git_sha)

    ignore_patterns = global_config.get_project_ignore_patterns(cwd)
    files_removed = 0
    files_written = 0
    warnings: List[Dict] = []

    # Remove files not expected at this bead (CAS manifest and/or git tree)
    for root, dirs, files in os.walk(cwd):
        dirs[:] = [
            d for d in dirs
            if not is_ignored(
                (Path(root) / d).relative_to(cwd).as_posix() + "/",
                ignore_patterns,
            ) and not _is_in_vault(Path(root) / d)
        ]
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(cwd).as_posix()
            if is_ignored(rel_path, ignore_patterns):
                continue
            if _is_in_vault(file_path):
                continue
            if rel_path not in paths_expected:
                try:
                    os.remove(file_path)
                    files_removed += 1
                except OSError as exc:
                    logger.warning("Could not remove %s: %s", file_path, exc)

    if target_bead.git_sha and git_repo_ctx is not None:
        ok = await asyncio.to_thread(git_checkout_detach, git_repo_ctx, target_bead.git_sha)
        if not ok:
            audit("GIT_CHECKOUT_FAILED", {"bead_id": target_bead.bead_id})
            return _err(
                "GIT_CHECKOUT_FAILED",
                "git checkout failed; ensure git is available and commit exists.",
            )

    # Restore CAS-backed manifest entries (subset after git pruning)
    for rel_path, entry in target_bead.manifest.items():
        try:
            target_path = assert_safe_path(cwd, rel_path)
        except SecurityError:
            return _err("PATH_TRAVERSAL", f"Manifest path '{rel_path}' is outside CWD")

        try:
            raw_bytes = read_blob(entry.sha256)
        except CASStorageError as exc:
            code = str(exc)
            return _err(code, f"Blob error for '{rel_path}'")

        result = scan_for_injection(raw_bytes, entry.mime_type)
        if result:
            code, detail = result
            warnings.append({"path": rel_path, "code": code, "detail": detail})

        def write_file(p: Path, data: bytes):
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    try:
                        p.chmod(0o666)
                    except OSError:
                        pass
            with open(p, "wb") as f:
                f.write(data)
                
        try:
            await asyncio.to_thread(write_file, target_path, raw_bytes)
            files_written += 1
        except OSError as exc:
            warnings.append({"path": rel_path, "code": "RESTORE_FAILED", "detail": str(exc)})

    resp = {
        "restored_bead_id": target_bead.bead_id,
        "files_written":    files_written,
        "files_removed":    files_removed,
        "warnings":         warnings,
    }
    if warning_msg:
        resp["notice"] = warning_msg

    return _ok(resp)


async def _get_summary_delta(arguments: dict) -> List[TextContent]:
    try:
        inp = GetSummaryDeltaInput.model_validate(arguments)
    except Exception as exc:
        return _err("INVALID_INPUT", str(exc))

    bead_a = find_bead(inp.bead_a)
    bead_b = find_bead(inp.bead_b)

    if not bead_a or not bead_b:
        missing = []
        if not bead_a:
            missing.append(inp.bead_a)
        if not bead_b:
            missing.append(inp.bead_b)
        return _err("BEAD_NOT_FOUND", "Bead(s) not found", {"missing": missing})

    decisions_added   = list(set(bead_b.decisions) - set(bead_a.decisions))
    decisions_removed = list(set(bead_a.decisions) - set(bead_b.decisions))
    todos_resolved    = list(set(bead_a.todos) - set(bead_b.todos))
    todos_added       = list(set(bead_b.todos) - set(bead_a.todos))

    files_added: List[str] = []
    files_removed: List[str] = []
    files_modified: List[str] = []
    files_unchanged = 0

    for path, entry_b in bead_b.manifest.items():
        if path not in bead_a.manifest:
            files_added.append(path)
        elif entry_b.sha256 != bead_a.manifest[path].sha256:
            files_modified.append(path)
        else:
            files_unchanged += 1

    for path in bead_a.manifest:
        if path not in bead_b.manifest:
            files_removed.append(path)

    return _ok({
        "summary_a": bead_a.summary,
        "summary_b": bead_b.summary,
        "decisions": {"added": decisions_added, "removed": decisions_removed},
        "todos":     {"resolved": todos_resolved, "added": todos_added},
        "files": {
            "added":     files_added,
            "removed":   files_removed,
            "modified":  files_modified,
            "unchanged": files_unchanged,
        },
    })


async def _squash_milestone(arguments: dict) -> List[TextContent]:
    try:
        inp = SquashMilestoneInput.model_validate(arguments)
    except Exception as exc:
        return _err("INVALID_INPUT", str(exc))

    key = get_vault_key()
    cwd = Path(os.getcwd())
    try:
        result = await asyncio.to_thread(
            squash_milestone_range,
            inp.project_id,
            inp.first_bead_id,
            inp.last_bead_id,
            inp.milestone_summary,
            cwd,
            key,
            inp.prune_git_blobs,
            inp.step_type,
        )
    except SquashError as exc:
        return _err(exc.code, str(exc))

    if inp.prune_git_blobs:
        await asyncio.to_thread(run_gc_collect)

    audit(
        "SQUASH_MILESTONE",
        {"project_id": inp.project_id, "detail": result},
    )
    return _ok(result)


async def _gc_collect(arguments: dict) -> List[TextContent]:
    _ = arguments
    await asyncio.to_thread(run_gc_collect)
    audit("GC_COLLECT", {})
    return _ok({"status": "ok"})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

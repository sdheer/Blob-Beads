"""
git_bridge.py — Locate repos, read commits, compare manifests to git blobs.

Uses the git CLI on PATH; failures return empty/false so callers can skip pruning.
"""

from __future__ import annotations

import hashlib
import mimetypes
import subprocess
from pathlib import Path
from typing import Dict, Optional, Set

from mcp_temporal_vault.models import ManifestEntry


def find_git_root(cwd: Path) -> Optional[Path]:
    """Return resolved repo root containing `.git`, or None."""
    cur = cwd.resolve()
    while True:
        git_marker = cur / ".git"
        if git_marker.exists():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def _git(repo_root: Path, *args: str, stdin: Optional[bytes] = None) -> tuple[int, bytes, bytes]:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        stdin=subprocess.PIPE if stdin is not None else None,
        input=stdin,
        timeout=120,
    )
    return proc.returncode, proc.stdout or b"", proc.stderr or b""


def get_head_sha(repo_root: Path) -> Optional[str]:
    code, out, _ = _git(repo_root, "rev-parse", "HEAD")
    if code != 0:
        return None
    hx = out.decode().strip().lower()
    if len(hx) == 40 and all(c in "0123456789abcdef" for c in hx):
        return hx
    return None


def is_clean_worktree(repo_root: Path) -> bool:
    code, out, _ = _git(repo_root, "status", "--porcelain")
    return code == 0 and not out.strip()


def read_git_blob(repo_root: Path, commit: str, rel_path: str) -> Optional[tuple[str, int]]:
    """Return (sha256_hex, byte_length) for blob at commit:path."""
    spec = f"{commit}:{rel_path}"
    code, out, _ = _git(repo_root, "show", spec)
    if code != 0:
        return None
    return hashlib.sha256(out).hexdigest(), len(out)


def file_sha256_at_commit(repo_root: Path, commit: str, rel_path: str) -> Optional[str]:
    """SHA-256 hex of object bytes at commit:path, or None if missing/error."""
    blob = read_git_blob(repo_root, commit, rel_path)
    return blob[0] if blob else None


def manifest_entry_at_commit(
    repo_root: Path, commit: str, rel_path: str
) -> Optional[ManifestEntry]:
    blob = read_git_blob(repo_root, commit, rel_path)
    if blob is None:
        return None
    digest, size = blob
    mime, _ = mimetypes.guess_type(rel_path)
    return ManifestEntry(sha256=digest, mime_type=mime or "application/octet-stream", size=size)


def tracked_paths_at_commit(repo_root: Path, commit: str) -> Set[str]:
    """All tracked blob paths (posix relpaths) at commit."""
    code, out, _ = _git(repo_root, "ls-tree", "-r", "--name-only", commit)
    if code != 0:
        return set()
    return {line.strip().replace("\\", "/") for line in out.decode().splitlines() if line.strip()}


def manifest_paths_satisfied_by_git(
    repo_root: Path,
    commit: str,
    manifest: Dict[str, ManifestEntry],
) -> Set[str]:
    """Paths whose CAS sha256 matches git blob content at commit."""
    satisfied: Set[str] = set()
    for rel_path, entry in manifest.items():
        git_digest = file_sha256_at_commit(repo_root, commit, rel_path)
        if git_digest is not None and git_digest == entry.sha256:
            satisfied.add(rel_path)
    return satisfied


def trim_manifest_for_git(
    manifest: Dict[str, ManifestEntry],
    satisfied_paths: Set[str],
) -> Dict[str, ManifestEntry]:
    """Drop manifest entries reproducible from git at prune time."""
    return {p: e for p, e in manifest.items() if p not in satisfied_paths}


def git_checkout_detach(repo_root: Path, commit: str) -> bool:
    """Force checkout commit (detached HEAD). Returns False on failure."""
    code, _, _ = _git(repo_root, "checkout", "--force", commit)
    return code == 0


def cwd_inside_git_repo(cwd: Path, repo_root: Path) -> bool:
    try:
        cwd.resolve().relative_to(repo_root.resolve())
        return True
    except ValueError:
        return False

"""
test_server.py — Integration tests for MCP tool handlers.

These tests call the internal async handler functions directly (bypassing
the MCP transport layer) to verify end-to-end pipeline behaviour.
"""

import json
import os
import uuid
import base64
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.server import call_tool


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Isolate vault and CWD for every test."""
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    monkeypatch.chdir(tmp_path)
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("MCP_VAULT_KEY", key)
    return tmp_path


def _parse(result) -> dict:
    """Parse the first TextContent item from a tool response."""
    return json.loads(result[0].text)

async def _do_save(arguments: dict) -> dict:
    from mcp_temporal_vault import server
    res = _parse(await call_tool("save_state", arguments))
    if "status" in res and res["status"] == "pending":
        if server._ACTIVE_SAVE_TASK:
            await server._ACTIVE_SAVE_TASK
        from mcp_temporal_vault.beads import get_last_bead
        last = get_last_bead(arguments.get("project_id", ""))
        if not last:
            raise RuntimeError("Save failed or bead not found")
        return {"bead_id": last.bead_id}
    return res


# ---------------------------------------------------------------------------
# save_state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_save_state_returns_bead_id(isolated_env):
    (isolated_env / "app.py").write_text("print('hello')")
    res = await _do_save({
        "project_id": "my-project",
        "summary": "Initial commit",
    })
    assert "bead_id" in res
    assert len(res["bead_id"]) == 36  # UUID v4


@pytest.mark.asyncio
async def test_save_state_invalid_project_id(isolated_env):
    """project_id with slashes or traversal chars should return INVALID_INPUT."""
    res = _parse(await call_tool("save_state", {
        "project_id": "../../evil",
        "summary": "bad",
    }))
    assert res["error"]["code"] == "INVALID_INPUT"


@pytest.mark.asyncio
async def test_save_state_response_is_valid_json(isolated_env):
    """Tool responses must always be parseable JSON, even on error."""
    # Malformed input that would previously break f-string JSON
    res_text = (await call_tool("save_state", {
        "project_id": 'x"y',  # quote in project_id
        "summary": "inject\" attempt",
    }))[0].text
    # Must not raise
    parsed = json.loads(res_text)
    assert "error" in parsed


# ---------------------------------------------------------------------------
# list_states
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_states_empty():
    res = _parse(await call_tool("list_states", {"project_id": "empty-proj"}))
    assert res == []


@pytest.mark.asyncio
async def test_list_states_returns_beads_in_order(isolated_env):
    (isolated_env / "file.txt").write_text("v1")
    await _do_save({"project_id": "proj", "summary": "step 1"})
    (isolated_env / "file.txt").write_text("v2")
    await _do_save({"project_id": "proj", "summary": "step 2"})

    res = _parse(await call_tool("list_states", {"project_id": "proj"}))
    assert len(res) == 2
    # Ordered timestamp DESC
    assert res[0]["timestamp"] >= res[1]["timestamp"]
    assert res[0]["summary"] == "step 2"


@pytest.mark.asyncio
async def test_list_states_has_required_fields(isolated_env):
    (isolated_env / "f.txt").write_text("data")
    await _do_save({"project_id": "p", "summary": "s"})
    items = _parse(await call_tool("list_states", {"project_id": "p"}))
    assert len(items) == 1
    item = items[0]
    for field in ("bead_id", "parent_id", "timestamp", "step_type", "summary", "file_count"):
        assert field in item


# ---------------------------------------------------------------------------
# checkout_state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_checkout_state_restores_file(isolated_env):
    """checkout_state should restore original file content."""
    (isolated_env / "hello.txt").write_text("original")
    save1 = await _do_save({"project_id": "p", "summary": "v1"})
    bead_id = save1["bead_id"]

    (isolated_env / "hello.txt").write_text("modified")
    await _do_save({"project_id": "p", "summary": "v2"})

    res = _parse(await call_tool("checkout_state", {"bead_id": bead_id, "force": True}))
    assert res["restored_bead_id"] == bead_id
    assert (isolated_env / "hello.txt").read_text() == "original"


@pytest.mark.asyncio
async def test_checkout_state_dirty_guard(isolated_env):
    """Without force=true, dirty CWD should return DIRTY_WORKING_DIR."""
    (isolated_env / "file.txt").write_text("v1")
    save1 = await _do_save({"project_id": "p", "summary": "v1"})
    bead_id = save1["bead_id"]

    # Modify without saving
    (isolated_env / "file.txt").write_text("unsaved change")

    res = _parse(await call_tool("checkout_state", {"bead_id": bead_id}))
    assert res["error"]["code"] == "DIRTY_WORKING_DIR"


@pytest.mark.asyncio
async def test_checkout_state_not_found(isolated_env):
    res = _parse(await call_tool("checkout_state", {"bead_id": "no-such-bead"}))
    assert res["error"]["code"] == "BEAD_NOT_FOUND"


@pytest.mark.asyncio
async def test_checkout_removes_extra_files(isolated_env):
    """Files absent from the target bead's manifest should be removed."""
    (isolated_env / "original.txt").write_text("keep")
    save1 = await _do_save({"project_id": "p", "summary": "v1"})
    bead_id = save1["bead_id"]

    # Add a new file and save again
    (isolated_env / "extra.txt").write_text("extra")
    await _do_save({"project_id": "p", "summary": "v2"})

    # Check out the original state (force because CWD now differs)
    await call_tool("checkout_state", {"bead_id": bead_id, "force": True})

    assert not (isolated_env / "extra.txt").exists()
    assert (isolated_env / "original.txt").exists()


# ---------------------------------------------------------------------------
# get_summary_delta
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_summary_delta_file_modified(isolated_env):
    (isolated_env / "app.py").write_text("version 1")
    save1 = await _do_save({"project_id": "p", "summary": "v1"})

    (isolated_env / "app.py").write_text("version 2")
    save2 = await _do_save({"project_id": "p", "summary": "v2"})

    delta = _parse(await call_tool("get_summary_delta", {
        "bead_a": save1["bead_id"],
        "bead_b": save2["bead_id"],
    }))

    assert "app.py" in delta["files"]["modified"]
    assert delta["files"]["added"] == []
    assert delta["files"]["removed"] == []


@pytest.mark.asyncio
async def test_get_summary_delta_file_added(isolated_env):
    (isolated_env / "a.py").write_text("a")
    save1 = await _do_save({"project_id": "p", "summary": "v1"})

    (isolated_env / "b.py").write_text("b")
    save2 = await _do_save({"project_id": "p", "summary": "v2"})

    delta = _parse(await call_tool("get_summary_delta", {
        "bead_a": save1["bead_id"],
        "bead_b": save2["bead_id"],
    }))
    assert "b.py" in delta["files"]["added"]


@pytest.mark.asyncio
async def test_get_summary_delta_bead_not_found(isolated_env):
    res = _parse(await call_tool("get_summary_delta", {
        "bead_a": "nonexistent-a",
        "bead_b": "nonexistent-b",
    }))
    assert res["error"]["code"] == "BEAD_NOT_FOUND"


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_tool_returns_error(isolated_env):
    res = _parse(await call_tool("no_such_tool", {}))
    assert res["error"]["code"] == "UNKNOWN_TOOL"


# ---------------------------------------------------------------------------
# Encryption end-to-end
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_save_and_checkout_encrypted(isolated_env, monkeypatch):
    """Full round-trip with AES-GCM encryption enabled."""
    key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("MCP_VAULT_KEY", key)

    (isolated_env / "secret.txt").write_text("classified content")
    save1 = await _do_save({"project_id": "p", "summary": "encrypted"})

    (isolated_env / "secret.txt").write_text("changed")
    await _do_save({"project_id": "p", "summary": "v2"})

    res = _parse(await call_tool("checkout_state", {
        "bead_id": save1["bead_id"],
        "force": True,
    }))
    assert res["restored_bead_id"] == save1["bead_id"]
    assert (isolated_env / "secret.txt").read_text() == "classified content"


# ---------------------------------------------------------------------------
# gc_collect / squash_milestone / git_sha
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gc_collect_tool(isolated_env):
    res = _parse(await call_tool("gc_collect", {}))
    assert res["status"] == "ok"


@pytest.mark.asyncio
async def test_squash_milestone_empty_project(isolated_env):
    res = _parse(
        await call_tool(
            "squash_milestone",
            {
                "project_id": "noproj",
                "first_bead_id": "x",
                "last_bead_id": "y",
                "milestone_summary": "ms",
            },
        )
    )
    assert res["error"]["code"] == "EMPTY_PROJECT"


needs_git = pytest.mark.skipif(not shutil.which("git"), reason="git not on PATH")


@needs_git
@pytest.mark.asyncio
async def test_save_state_sets_git_sha_on_clean_repo(isolated_env, monkeypatch):
    """Vault dir must not live inside the git repo or status is dirty (untracked)."""
    ext_root = isolated_env.parent / f"vault_git_{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(global_config, "vault_dir", ext_root / ".mcp_vault")

    subprocess.run(["git", "init"], cwd=isolated_env, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "t@test"], cwd=isolated_env, check=True
    )
    subprocess.run(["git", "config", "user.name", "t"], cwd=isolated_env, check=True)
    (isolated_env / "tracked.txt").write_text("v1")
    subprocess.run(["git", "add", "tracked.txt"], cwd=isolated_env, check=True)
    subprocess.run(["git", "commit", "-m", "m"], cwd=isolated_env, check=True)

    await _do_save({"project_id": "gitproj", "summary": "clean snap"})
    from mcp_temporal_vault.beads import get_last_bead

    last = get_last_bead("gitproj")
    assert last.git_sha is not None and len(last.git_sha) == 40


@needs_git
@pytest.mark.asyncio
async def test_save_state_clears_git_sha_when_dirty(isolated_env, monkeypatch):
    ext_root = isolated_env.parent / f"vault_dirty_{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(global_config, "vault_dir", ext_root / ".mcp_vault")

    subprocess.run(["git", "init"], cwd=isolated_env, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "t@test"], cwd=isolated_env, check=True
    )
    subprocess.run(["git", "config", "user.name", "t"], cwd=isolated_env, check=True)
    (isolated_env / "tracked.txt").write_text("v1")
    subprocess.run(["git", "add", "tracked.txt"], cwd=isolated_env, check=True)
    subprocess.run(["git", "commit", "-m", "m"], cwd=isolated_env, check=True)

    (isolated_env / "untracked.txt").write_text("dirty")

    await _do_save({"project_id": "dirtyproj", "summary": "dirty snap"})
    from mcp_temporal_vault.beads import get_last_bead

    last = get_last_bead("dirtyproj")
    assert last.git_sha is None


@pytest.mark.asyncio
async def test_squash_milestone_merges_beads(isolated_env):
    (isolated_env / "a.py").write_text("a")
    s1 = await _do_save({"project_id": "sq", "summary": "one", "decisions": ["d1"]})
    (isolated_env / "a.py").write_text("b")
    s2 = await _do_save(
        {"project_id": "sq", "summary": "two", "todos": ["t1"], "decisions": ["d2"]}
    )

    res = _parse(
        await call_tool(
            "squash_milestone",
            {
                "project_id": "sq",
                "first_bead_id": s1["bead_id"],
                "last_bead_id": s2["bead_id"],
                "milestone_summary": "Merged milestone",
            },
        )
    )
    assert res["beads_removed"] == 2
    assert res["milestone_bead_id"]

    from mcp_temporal_vault.beads import find_bead, iter_beads_forward

    beads = list(iter_beads_forward("sq"))
    assert len(beads) == 1
    m = beads[0]
    assert m.step_type == "milestone"
    assert "Merged milestone" in m.summary
    assert "d1" in m.decisions and "d2" in m.decisions
    assert "t1" in m.todos
    assert find_bead(s1["bead_id"]) is None

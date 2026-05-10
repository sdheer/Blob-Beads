"""
test_server.py — Integration tests for MCP tool handlers.

These tests call the internal async handler functions directly (bypassing
the MCP transport layer) to verify end-to-end pipeline behaviour.
"""

import json
import os
import base64
import time
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
async def test_save_state_invalid_project_id():
    """project_id with slashes or traversal chars should return INVALID_INPUT."""
    res = _parse(await call_tool("save_state", {
        "project_id": "../../evil",
        "summary": "bad",
    }))
    assert res["error"]["code"] == "INVALID_INPUT"


@pytest.mark.asyncio
async def test_save_state_response_is_valid_json():
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
async def test_checkout_state_not_found():
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
async def test_get_summary_delta_bead_not_found():
    res = _parse(await call_tool("get_summary_delta", {
        "bead_a": "nonexistent-a",
        "bead_b": "nonexistent-b",
    }))
    assert res["error"]["code"] == "BEAD_NOT_FOUND"


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unknown_tool_returns_error():
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

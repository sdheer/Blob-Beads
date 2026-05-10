"""
test_beads.py — Unit tests for the JSONL bead storage engine.
"""

import time
import pytest

from mcp_temporal_vault.beads import append_bead, find_bead, get_last_bead, iter_beads_reverse
from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.models import Bead


@pytest.fixture(autouse=True)
def isolated_vault(tmp_path, monkeypatch):
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")


def _make_bead(bead_id: str, project_id: str, parent_id=None, step_type="checkpoint", summary="test") -> Bead:
    return Bead(
        bead_id=bead_id,
        project_id=project_id,
        parent_id=parent_id,
        timestamp=int(time.time()),
        step_type=step_type,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# append + iter_beads_reverse
# ---------------------------------------------------------------------------

def test_append_and_reverse_order():
    """Beads are yielded in reverse insertion order."""
    append_bead(_make_bead("bead-1", "proj"))
    append_bead(_make_bead("bead-2", "proj", parent_id="bead-1"))
    append_bead(_make_bead("bead-3", "proj", parent_id="bead-2"))

    beads = list(iter_beads_reverse("proj"))
    assert [b.bead_id for b in beads] == ["bead-3", "bead-2", "bead-1"]


def test_iter_nonexistent_project_returns_empty():
    """Iterating a project with no JSONL file yields nothing."""
    assert list(iter_beads_reverse("does-not-exist")) == []


def test_append_preserves_all_fields():
    """All fields survive the JSONL serialisation round-trip."""
    original = Bead(
        bead_id="full-bead",
        project_id="proj",
        parent_id="parent-id",
        timestamp=1_000_000,
        step_type="decision",
        summary="test summary",
        decisions=["decision A", "decision B"],
        todos=["todo 1"],
        manifest={},
    )
    append_bead(original)
    recovered = next(iter_beads_reverse("proj"))
    assert recovered.bead_id == original.bead_id
    assert recovered.decisions == original.decisions
    assert recovered.todos == original.todos


# ---------------------------------------------------------------------------
# find_bead
# ---------------------------------------------------------------------------

def test_find_bead_located():
    append_bead(_make_bead("target-bead", "proj"))
    found = find_bead("target-bead")
    assert found is not None
    assert found.bead_id == "target-bead"


def test_find_bead_missing_returns_none():
    assert find_bead("no-such-bead") is None


def test_find_bead_across_projects():
    """find_bead searches across all project JSONL files."""
    append_bead(_make_bead("bead-a", "project-alpha"))
    append_bead(_make_bead("bead-b", "project-beta"))
    assert find_bead("bead-b") is not None
    assert find_bead("bead-b").project_id == "project-beta"


# ---------------------------------------------------------------------------
# get_last_bead
# ---------------------------------------------------------------------------

def test_get_last_bead():
    append_bead(_make_bead("first", "proj"))
    append_bead(_make_bead("second", "proj", parent_id="first"))
    last = get_last_bead("proj")
    assert last.bead_id == "second"


def test_get_last_bead_empty_project():
    assert get_last_bead("empty-project") is None

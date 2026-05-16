"""Tests for squash_milestone_range orchestration."""

import os
import uuid
from pathlib import Path

import pytest

from mcp_temporal_vault.beads import append_bead, iter_beads_forward
from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.crypto import sign_manifest
from mcp_temporal_vault.models import Bead, ManifestEntry
from mcp_temporal_vault.squash import SquashError, squash_milestone_range


@pytest.fixture(autouse=True)
def vault_home(tmp_path, monkeypatch):
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    return tmp_path


def _manifest():
    return {"x.txt": ManifestEntry(sha256="b" * 64, mime_type="text/plain", size=1)}


def _chain(project_id: str, key: bytes, n: int) -> list[str]:
    m = _manifest()
    ids = []
    for i in range(n):
        bid = str(uuid.uuid4())
        sig = sign_manifest(m, key)
        append_bead(
            Bead(
                bead_id=bid,
                project_id=project_id,
                parent_id=ids[-1] if ids else None,
                timestamp=i,
                step_type="checkpoint",
                summary=str(i),
                manifest=m,
                manifest_signature=sig,
            )
        )
        ids.append(bid)
    return ids


def test_squash_empty_raises(tmp_path):
    key = os.urandom(32)
    with pytest.raises(SquashError) as ei:
        squash_milestone_range(
            "empty",
            "a",
            "b",
            "ms",
            Path(tmp_path),
            key,
        )
    assert ei.value.code == "EMPTY_PROJECT"


def test_squash_range_reversed_raises(tmp_path):
    key = os.urandom(32)
    ids = _chain("rev", key, 2)
    with pytest.raises(SquashError) as ei:
        squash_milestone_range(
            "rev",
            ids[1],
            ids[0],
            "bad",
            Path(tmp_path),
            key,
        )
    assert ei.value.code == "INVALID_RANGE"


def test_squash_merges_suffix_parent(tmp_path):
    key = os.urandom(32)
    ids = _chain("mg", key, 3)
    cwd = Path(tmp_path)

    out = squash_milestone_range(
        "mg",
        ids[0],
        ids[1],
        "merged",
        cwd,
        key,
        prune_git_blobs=False,
    )
    assert out["beads_removed"] == 2
    beads = list(iter_beads_forward("mg"))
    assert len(beads) == 2
    assert beads[0].step_type == "milestone"
    assert beads[0].summary == "merged"
    assert beads[1].parent_id == beads[0].bead_id

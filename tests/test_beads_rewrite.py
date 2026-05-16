"""Tests for iter_beads_forward and rewrite_project_beads."""

import os
import uuid

import pytest

from mcp_temporal_vault.beads import append_bead, iter_beads_forward, rewrite_project_beads
from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.crypto import sign_manifest
from mcp_temporal_vault.models import Bead, ManifestEntry


@pytest.fixture(autouse=True)
def vault_home(tmp_path, monkeypatch):
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    return tmp_path


def _hx():
    return "a" * 64


def test_iter_forward_order():
    key = os.urandom(32)
    manifest = {"f.txt": ManifestEntry(sha256=_hx(), mime_type="text/plain", size=1)}
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for i, bid in enumerate(ids):
        sig = sign_manifest(manifest, key)
        append_bead(
            Bead(
                bead_id=bid,
                project_id="proj",
                parent_id=ids[i - 1] if i else None,
                timestamp=i,
                step_type="checkpoint",
                summary=f"s{i}",
                manifest=manifest,
                manifest_signature=sig,
            )
        )
    forward = [b.bead_id for b in iter_beads_forward("proj")]
    assert forward == ids


def test_rewrite_truncates_and_preserves_order():
    key = os.urandom(32)
    manifest = {"f.txt": ManifestEntry(sha256=_hx(), mime_type="text/plain", size=1)}
    ids = [str(uuid.uuid4()) for _ in range(4)]
    beads = []
    for i, bid in enumerate(ids):
        sig = sign_manifest(manifest, key)
        beads.append(
            Bead(
                bead_id=bid,
                project_id="p2",
                parent_id=ids[i - 1] if i else None,
                timestamp=i,
                step_type="checkpoint",
                summary=str(i),
                manifest=manifest,
                manifest_signature=sig,
            )
        )
        append_bead(beads[-1])

    kept = [beads[0], beads[3]]
    rewrite_project_beads("p2", kept)
    out = list(iter_beads_forward("p2"))
    assert len(out) == 2
    assert [b.bead_id for b in out] == [ids[0], ids[3]]

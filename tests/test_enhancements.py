# tests/test_enhancements.py
"""High‑level integration tests for the new security enhancements.
These tests run against the in‑process modules – no external server is started.
"""
import os
import json
import shutil
import base64
from pathlib import Path

import pytest

from mcp_temporal_vault import audit, quota, key_manager, crypto, cas, config, security

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def reset_vault(tmp_path: Path):
    """Create a fresh vault directory under ``tmp_path`` and point the global config at it."""
    vault_dir = tmp_path / ".mcp_vault"
    vault_dir.mkdir()
    # write a minimal config.json (empty) – config reads from ~/.mcp_vault/config.json by default
    (vault_dir / "config.json").write_text(json.dumps({}), encoding="utf-8")
    # point the global config to this directory
    config.global_config.vault_dir = vault_dir
    # ensure audit log points to the new location
    audit.AUDIT_LOG = vault_dir / "audit.log"
    if not audit.AUDIT_LOG.exists():
        audit.AUDIT_LOG.touch(mode=0o600)
    else:
        os.chmod(audit.AUDIT_LOG, 0o600)
        
    # Reset the logger handler so it points to the new file
    if audit._handler is not None:
        audit._logger.removeHandler(audit._handler)
        audit._handler.close()
        audit._handler = None

def read_audit() -> list[dict]:
    """Return the audit log as a list of JSON objects."""
    with open(audit.AUDIT_LOG, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

# ---------------------------------------------------------------------------
# 1. Audit logging
# ---------------------------------------------------------------------------

def test_audit_logging(tmp_path: Path):
    reset_vault(tmp_path)
    audit.audit("TEST_EVENT", {"foo": "bar"})
    entries = read_audit()
    assert any(e["event"] == "TEST_EVENT" and e["foo"] == "bar" for e in entries)

# ---------------------------------------------------------------------------
# 2. Quota enforcement
# ---------------------------------------------------------------------------

def test_quota_enforced(tmp_path: Path, monkeypatch):
    reset_vault(tmp_path)
    # Mock usage to simulate being over quota
    monkeypatch.setattr(quota, "_project_usage", lambda pid: 1_200_000_000)
    project_id = "proj_quota"
    # Any store operation should raise because the project is over its limit.
    with pytest.raises(RuntimeError, match="exceeds storage quota"):
        cas.store_blob(b"small data", project_id=project_id)

# ---------------------------------------------------------------------------
# 3. Garbage collection removes unreferenced blobs
# ---------------------------------------------------------------------------
def test_gc_deletes_orphan_blobs(tmp_path: Path):
    reset_vault(tmp_path)
    # Store a blob without associating it with any bead (no manifest entry).
    data = b"orphan"
    digest = cas.store_blob(data, project_id="proj_gc")
    # Ensure the blob exists on disk.
    blob_path = cas._get_blob_path(digest, False)
    assert blob_path.is_file()
    # Run GC – it should delete the orphan.
    quota.gc_collect()
    assert not blob_path.exists()

# ---------------------------------------------------------------------------
# 4. Key handling – file‑based secret
# ---------------------------------------------------------------------------
def test_key_file_loading(tmp_path: Path):
    reset_vault(tmp_path)
    # Generate a proper 32‑byte key and write it to the expected file.
    key_bytes = os.urandom(32)
    key_b64 = base64.urlsafe_b64encode(key_bytes).decode()
    key_path = config.global_config.vault_dir / "key"
    key_path.write_text(key_b64)
    os.chmod(key_path, 0o600)
    # The manager should now return the exact key.
    loaded = key_manager.get_vault_key()
    assert loaded == key_bytes
    # Encryption round‑trip works.
    payload = b"secret payload"
    enc = crypto.encrypt_blob(payload, loaded)
    dec = crypto.decrypt_blob(enc, loaded)
    assert dec == payload

def test_missing_key_fails_on_encrypted_blob(tmp_path: Path):
    reset_vault(tmp_path)
    # Write a key file temporarily to store a blob
    key_bytes = os.urandom(32)
    key_b64 = base64.urlsafe_b64encode(key_bytes).decode()
    key_path = config.global_config.vault_dir / "key"
    key_path.write_text(key_b64)
    os.chmod(key_path, 0o600)
    
    data = b"secret data"
    digest = cas.store_blob(data, project_id="proj_fail")
    
    # Now remove the key
    key_path.unlink()
    
    # Reading should fail
    with pytest.raises(cas.CASStorageError, match="MCP_VAULT_KEY is not set"):
        cas.read_blob(digest)

# ---------------------------------------------------------------------------
# 5. Store_blob respects quota and encrypts when key present
# ---------------------------------------------------------------------------
def test_store_blob_encrypts_when_key(tmp_path: Path):
    reset_vault(tmp_path)
    # Write a key file.
    key_bytes = os.urandom(32)
    (config.global_config.vault_dir / "key").write_text(
        base64.urlsafe_b64encode(key_bytes).decode()
    )
    os.chmod(config.global_config.vault_dir / "key", 0o600)
    data = b"plain data"
    digest = cas.store_blob(data, project_id="proj_enc")
    # The raw file on disk should be encrypted (nonce+ct) – size > original.
    blob_path = cas._get_blob_path(digest, True)
    raw_on_disk = blob_path.read_bytes()
    assert len(raw_on_disk) > len(data)
    # Decrypt and then decompress to get original back.
    import zstandard as zstd
    decrypted = crypto.decrypt_blob(raw_on_disk, key_bytes)
    dctx = zstd.ZstdDecompressor()
    assert dctx.decompress(decrypted) == data

# ---------------------------------------------------------------------------
# 6. fingerprint_cwd respects vault directory (no false dirty)
# ---------------------------------------------------------------------------
def test_fingerprint_ignores_vault_dir(tmp_path: Path, monkeypatch):
    reset_vault(tmp_path)
    # Create a dummy project with a single bead.
    from mcp_temporal_vault import beads, models
    project = "proj_fp"
    bead = models.Bead(
        bead_id="b1",
        project_id=project,
        parent_id=None,
        timestamp=0,
        step_type="checkpoint",
        summary="test",
    )
    beads.append_bead(bead)
    # The CWD is the temporary repo root – the vault dir lives inside it.
    cwd = tmp_path
    # Inject a dummy manifest that matches the current state.
    manifest = bead.manifest
    assert not security.fingerprint_cwd(cwd, manifest)  # should be clean

"""End of test suite."""

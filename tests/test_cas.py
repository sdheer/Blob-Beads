"""
test_cas.py — Unit tests for the Content-Addressable Storage engine.
"""

import base64
import hashlib
import os
from pathlib import Path

import pytest
import zstandard as zstd

from mcp_temporal_vault.cas import CASStorageError, read_blob, store_blob
from mcp_temporal_vault.config import global_config


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_vault(tmp_path, monkeypatch):
    """Redirect vault to a fresh temp directory for every test."""
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    monkeypatch.delenv("MCP_VAULT_KEY", raising=False)


@pytest.fixture()
def with_encryption(monkeypatch):
    """Enable AES-GCM encryption via the env var."""
    key = os.urandom(32)
    monkeypatch.setenv("MCP_VAULT_KEY", base64.urlsafe_b64encode(key).decode())
    return key


# ---------------------------------------------------------------------------
# Plaintext (no encryption) round-trip
# ---------------------------------------------------------------------------

def test_store_and_read_roundtrip():
    data = b"Hello, vault!"
    sha256 = store_blob(data)
    assert sha256 == hashlib.sha256(data).hexdigest()
    assert read_blob(sha256) == data


def test_store_returns_correct_sha256():
    data = b"deterministic content"
    sha256 = store_blob(data)
    assert sha256 == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_deduplication_skips_second_write(tmp_path, monkeypatch):
    """Storing the same content twice does not create a second file."""
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    data = b"Identical content"
    sha256_1 = store_blob(data)
    sha256_2 = store_blob(data)
    assert sha256_1 == sha256_2

    bucket = global_config.get_hashbucket_dir()
    blobs = list(bucket.rglob("*"))
    blob_files = [b for b in blobs if b.is_file()]
    assert len(blob_files) == 1


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_read_blob_missing():
    with pytest.raises(CASStorageError, match="BLOB_MISSING"):
        read_blob("a" * 64)  # valid-looking hash, no file on disk


def test_blob_too_large():
    """Decompressed content exceeding max_bytes raises BLOB_TOO_LARGE."""
    data = b"X" * 2048
    sha256 = store_blob(data)
    with pytest.raises(CASStorageError, match="BLOB_TOO_LARGE"):
        read_blob(sha256, max_bytes=512)


def test_blob_integrity_failure(tmp_path, monkeypatch):
    """Tampering with the on-disk .zst file raises BLOB_INTEGRITY_FAILURE."""
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    data = b"tamper me"
    sha256 = store_blob(data)

    # Corrupt the blob by overwriting with a different zstd payload
    prefix = sha256[:2]
    blob_path = global_config.get_hashbucket_dir() / prefix / f"{sha256}.zst"
    cctx = zstd.ZstdCompressor()
    blob_path.write_bytes(cctx.compress(b"different content"))

    with pytest.raises(CASStorageError, match="BLOB_INTEGRITY_FAILURE"):
        read_blob(sha256)


# ---------------------------------------------------------------------------
# AES-GCM encryption integration
# ---------------------------------------------------------------------------

def test_encrypted_store_and_read(with_encryption):
    """With MCP_VAULT_KEY set, blobs are stored as .enc.zst and round-trip correctly."""
    data = b"Encrypted blob content"
    sha256 = store_blob(data)
    assert read_blob(sha256) == data

    # Verify the encrypted file exists (not the plaintext variant)
    prefix = sha256[:2]
    enc_path = global_config.get_hashbucket_dir() / prefix / f"{sha256}.enc.zst"
    plain_path = global_config.get_hashbucket_dir() / prefix / f"{sha256}.zst"
    assert enc_path.exists()
    assert not plain_path.exists()


def test_encrypted_file_is_not_plaintext(with_encryption):
    """Raw bytes on disk should not be directly decompressible (they're encrypted)."""
    data = b"Super secret file"
    sha256 = store_blob(data)

    prefix = sha256[:2]
    enc_path = global_config.get_hashbucket_dir() / prefix / f"{sha256}.enc.zst"
    raw = enc_path.read_bytes()

    # Attempting to decompress the raw encrypted payload should fail
    dctx = zstd.ZstdDecompressor()
    with pytest.raises(Exception):
        dctx.decompress(raw)


def test_plaintext_fallback_without_key(tmp_path, monkeypatch):
    """
    A blob written without a key (plaintext .zst) can be read back even
    when MCP_VAULT_KEY is not set — backward compatibility check.
    """
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    monkeypatch.delenv("MCP_VAULT_KEY", raising=False)

    data = b"Legacy plaintext blob"
    sha256 = store_blob(data)
    assert read_blob(sha256) == data


def test_read_encrypted_without_key_raises(with_encryption, monkeypatch):
    """Reading an encrypted blob without the key set raises a CASStorageError."""
    data = b"Needs the key"
    sha256 = store_blob(data)

    # Now remove the key
    monkeypatch.delenv("MCP_VAULT_KEY", raising=False)

    with pytest.raises(CASStorageError, match="MCP_VAULT_KEY"):
        read_blob(sha256)

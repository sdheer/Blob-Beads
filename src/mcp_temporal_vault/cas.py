"""
cas.py — Content-Addressable Storage engine for blob management.

Storage layout:
    Plaintext blob:   hashbucket/{sha256[:2]}/{sha256}.zst
    Encrypted blob:   hashbucket/{sha256[:2]}/{sha256}.enc.zst

The SHA-256 CAS key is computed on the RAW (pre-compression) bytes so that
deduplication is content-based regardless of whether encryption is enabled.

On read, the encrypted extension is probed first; the plaintext extension is
used as a fallback so that vaults written before encryption was enabled
continue to work without migration.
"""

import hashlib
import io
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

import zstandard as zstd

from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.crypto import decrypt_blob, encrypt_blob, get_vault_key

logger = logging.getLogger(__name__)

_ENC_SUFFIX = ".enc.zst"
_PLAIN_SUFFIX = ".zst"


class CASStorageError(Exception):
    pass


def _get_blob_path(sha256_hex: str, encrypted: bool) -> Path:
    prefix = sha256_hex[:2]
    suffix = _ENC_SUFFIX if encrypted else _PLAIN_SUFFIX
    return global_config.get_hashbucket_dir() / prefix / f"{sha256_hex}{suffix}"


def _decompress(payload: bytes, max_bytes: int) -> bytes:
    """Decompresses a zstd payload with a size cap (decompression bomb guard)."""
    dctx = zstd.ZstdDecompressor()
    try:
        raw_bytes = dctx.stream_reader(io.BytesIO(payload)).read(max_bytes + 1)
    except Exception as exc:
        raise CASStorageError(f"Decompression error: {exc}") from exc
    if len(raw_bytes) > max_bytes:
        raise CASStorageError("BLOB_TOO_LARGE")
    return raw_bytes


def store_blob(raw_bytes: bytes, project_id: Optional[str] = None) -> str:
    """
    Compresses (and optionally encrypts) bytes, then stores in the hashbucket
    atomically via a temp-file rename.  Returns the hex SHA-256 of the raw bytes.

    Deduplication: if the target path already exists the write is skipped.
    Collision detection: if a *different* file already occupies the same path
    (same hash, different content — theoretically impossible for SHA-256 but
    guarded defensively) a CASStorageError('BLOB_COLLISION') is raised.
    """
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    # Enforce quota if a project identifier is supplied
    if project_id:
        from .quota import enforce_quota
        enforce_quota(project_id)
    key = get_vault_key()
    encrypted = key is not None
    blob_path = _get_blob_path(sha256, encrypted)

    if blob_path.exists():
        _verify_no_collision(blob_path, raw_bytes, key)
        return sha256

    # If switching modes (e.g. encryption just enabled), the other variant
    # might already exist — still counts as dedup.
    alt_path = _get_blob_path(sha256, not encrypted)
    if alt_path.exists():
        return sha256

    blob_path.parent.mkdir(parents=True, exist_ok=True)

    cctx = zstd.ZstdCompressor(level=global_config.zstd_level)
    payload = cctx.compress(raw_bytes)

    if encrypted:
        payload = encrypt_blob(payload, key)

    # Atomic write: write to tmp then os.replace
    fd, tmp_path = tempfile.mkstemp(dir=blob_path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp_path, blob_path)
    except Exception as exc:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise CASStorageError(f"Failed to write blob: {exc}") from exc

    return sha256

def store_blob_staged(raw_bytes: bytes, project_id: Optional[str] = None) -> Path:
    """
    Compresses (and optionally encrypts) bytes, then stores in the staging directory.
    Returns the path to the staged file (filename is the sha256 hex).
    """
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    if project_id:
        from .quota import enforce_quota
        enforce_quota(project_id)
        
    key = get_vault_key()
    encrypted = key is not None
    
    # Check if already in hashbucket (deduplication)
    final_path = _get_blob_path(sha256, encrypted)
    if final_path.exists() or _get_blob_path(sha256, not encrypted).exists():
        return Path() # Empty path indicates already exists
        
    staging_dir = global_config.get_staging_dir()
    staging_file = staging_dir / (sha256 + (_ENC_SUFFIX if encrypted else _PLAIN_SUFFIX))
    
    if staging_file.exists():
        return staging_file
        
    cctx = zstd.ZstdCompressor(level=global_config.zstd_level)
    payload = cctx.compress(raw_bytes)
    if encrypted:
        payload = encrypt_blob(payload, key)
        
    fd, tmp_path = tempfile.mkstemp(dir=staging_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp_path, staging_file)
    except Exception as exc:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise CASStorageError(f"Failed to stage blob: {exc}") from exc
        
    return staging_file

def commit_staging(staged_files: list) -> None:
    """Atomically moves staged files to their final hashbucket destination."""
    for staged_file in staged_files:
        if not staged_file.exists() or not staged_file.name:
            continue
            
        sha256 = staged_file.name.split('.')[0]
        encrypted = staged_file.name.endswith(_ENC_SUFFIX)
        final_path = _get_blob_path(sha256, encrypted)
        
        if final_path.exists():
            staged_file.unlink() # Already deduped
            continue
            
        final_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_file, final_path)

def clear_staging() -> None:
    """Deletes all files in the staging directory."""
    staging_dir = global_config.get_staging_dir()
    if not staging_dir.exists():
        return
    for f in staging_dir.iterdir():
        if f.is_file():
            try:
                f.unlink()
            except OSError:
                pass


def read_blob(sha256_hex: str, max_bytes: Optional[int] = None) -> bytes:
    """
    Reads, decrypts (if needed), and decompresses a blob by its SHA-256 hash.
    Probes for the encrypted variant first, then the plaintext variant.
    Enforces a max decompressed size cap to guard against decompression bombs.
    Verifies the SHA-256 of decompressed bytes matches the expected hash.
    """
    if max_bytes is None:
        max_bytes = global_config.max_file_size_mb * 1024 * 1024

    key = get_vault_key()

    # Probe encrypted path first, then plaintext (backward-compat)
    enc_path = _get_blob_path(sha256_hex, encrypted=True)
    plain_path = _get_blob_path(sha256_hex, encrypted=False)

    if enc_path.exists():
        blob_path = enc_path
        is_encrypted = True
    elif plain_path.exists():
        blob_path = plain_path
        is_encrypted = False
    else:
        raise CASStorageError("BLOB_MISSING")

    payload = blob_path.read_bytes()

    if is_encrypted:
        if key is None:
            raise CASStorageError(
                "Blob is encrypted but MCP_VAULT_KEY is not set. "
                "Set the environment variable to read this vault."
            )
        try:
            from cryptography.exceptions import InvalidTag
            payload = decrypt_blob(payload, key)
        except InvalidTag:
            raise CASStorageError("BLOB_INTEGRITY_FAILURE")
        except Exception as exc:
            raise CASStorageError(f"Decryption error: {exc}") from exc

    # Decompress with bomb guard
    raw_bytes = _decompress(payload, max_bytes)

    # Integrity check: SHA-256 of decompressed content must match the CAS key
    actual_hash = hashlib.sha256(raw_bytes).hexdigest()
    if actual_hash != sha256_hex:
        raise CASStorageError("BLOB_INTEGRITY_FAILURE")

    return raw_bytes


def _verify_no_collision(blob_path: Path, raw_bytes: bytes, key: Optional[bytes]) -> None:
    """Verify an existing blob at the same hash is not a different file (SHA-256 collision)."""
    try:
        payload = blob_path.read_bytes()
        is_encrypted = blob_path.name.endswith(_ENC_SUFFIX)
        if is_encrypted and key is not None:
            from cryptography.exceptions import InvalidTag
            try:
                payload = decrypt_blob(payload, key)
            except InvalidTag:
                raise CASStorageError("BLOB_COLLISION")
        max_bytes = global_config.max_file_size_mb * 1024 * 1024
        existing_raw = _decompress(payload, max_bytes)
        if existing_raw != raw_bytes:
            raise CASStorageError("BLOB_COLLISION")
    except CASStorageError:
        raise
    except Exception:
        pass  # If we can't verify, be conservative and allow the dedup

"""
crypto.py — AES-256-GCM encryption for local blob storage.

Encryption is required for normal use through the MCP server: ``call_tool``
loads the vault key first and returns ``MISSING_ENCRYPTION_KEY`` until a valid
key is configured (see ``mcp_temporal_vault.server``).

Keys are resolved by ``key_manager.get_vault_key``, in order:
    1. Environment variable ``MCP_VAULT_KEY`` (base64url-encoded 32-byte secret)
    2. File ``<vault_dir>/key`` (same encoding; must be mode ``600``)

Generate a key:
    python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"

When no key is available, lower-level CAS helpers may still read or write legacy
plaintext blobs for backward compatibility; the MCP entrypoint does not expose
that mode.

Wire format (encrypted blob):
    [ 12-byte nonce ][ ciphertext ][ 16-byte GCM auth tag ]

The SHA-256 CAS key is always computed on the RAW (pre-compression, pre-encryption)
bytes so that content-based deduplication is preserved regardless of nonces.
"""

import base64
import logging
import os
from typing import Optional
import hmac
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mcp_temporal_vault.key_manager import get_vault_key

logger = logging.getLogger(__name__)

_NONCE_LEN = 12


def _manifest_entries_dict(manifest_dict: dict) -> dict:
    """Canonical manifest payload mapping paths to entry fields."""
    return {
        k: {
            "sha256": v.sha256,
            "mime_type": v.mime_type,
            "size": getattr(v, "size", 0),
        }
        for k, v in manifest_dict.items()
    }


def sign_manifest(manifest_dict: dict, key: bytes, git_sha: Optional[str] = None) -> str:
    """Compute HMAC-SHA256 over manifest and optional git_sha (wrapped JSON)."""
    inner = _manifest_entries_dict(manifest_dict)
    payload_obj = {"git_sha": git_sha, "manifest": inner}
    serialized = json.dumps(payload_obj, sort_keys=True).encode("utf-8")
    return hmac.new(key, serialized, digestmod="sha256").hexdigest()


def verify_manifest(
    manifest_dict: dict,
    signature: str,
    key: bytes,
    git_sha: Optional[str] = None,
) -> bool:
    """Verify manifest signature; supports legacy manifest-only HMAC for old beads."""
    expected_new = sign_manifest(manifest_dict, key, git_sha)
    if hmac.compare_digest(expected_new, signature):
        return True
    if git_sha is None:
        legacy = json.dumps(_manifest_entries_dict(manifest_dict), sort_keys=True).encode(
            "utf-8"
        )
        expected_old = hmac.new(key, legacy, digestmod="sha256").hexdigest()
        return hmac.compare_digest(expected_old, signature)
    return False


def encrypt_blob(data: bytes, key: bytes) -> bytes:
    """
    Encrypts `data` using AES-256-GCM with a fresh random nonce.
    Returns: nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
    """
    nonce = os.urandom(_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext_and_tag


def decrypt_blob(data: bytes, key: bytes) -> bytes:
    """
    Decrypts an AES-256-GCM blob produced by `encrypt_blob`.
    Raises cryptography.exceptions.InvalidTag if the ciphertext was tampered.
    Raises ValueError if the data is too short to be a valid encrypted blob.
    """
    if len(data) < _NONCE_LEN + 16:
        raise ValueError("Encrypted blob is too short — data may be corrupt.")
    nonce = data[:_NONCE_LEN]
    ciphertext_and_tag = data[_NONCE_LEN:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
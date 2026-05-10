"""
crypto.py — AES-256-GCM encryption for local blob storage.

Encryption is opt-in via the MCP_VAULT_KEY environment variable.
If the variable is not set, blobs are stored as-is (plaintext compressed).

Key format:
    MCP_VAULT_KEY must be a base64url-encoded 32-byte secret.
    Generate with:
        python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"

Wire format (encrypted blob):
    [ 12-byte nonce ][ ciphertext ][ 16-byte GCM auth tag ]

The SHA-256 CAS key is always computed on the RAW (pre-compression, pre-encryption)
bytes so that content-based deduplication is preserved regardless of nonces.
"""

import base64
import logging
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac

from mcp_temporal_vault.key_manager import get_vault_key

logger = logging.getLogger(__name__)

_NONCE_LEN = 12  # 96-bit nonce for AES-GCM (NIST SP 800-38D recommended)

def sign_manifest(manifest_dict: dict, key: bytes) -> str:
    """Compute an HMAC-SHA256 signature for the manifest to detect tampering."""
    import json
    # Sort keys to ensure deterministic serialization
    serialized = json.dumps(
        {k: {"sha256": v.sha256, "mime_type": v.mime_type, "size": getattr(v, "size", 0)} 
         for k, v in manifest_dict.items()},
        sort_keys=True
    ).encode("utf-8")
    h = hmac.new(key, serialized, digestmod="sha256")
    return h.hexdigest()
    
def verify_manifest(manifest_dict: dict, signature: str, key: bytes) -> bool:
    """Verify the HMAC-SHA256 signature of the manifest."""
    expected = sign_manifest(manifest_dict, key)
    return hmac.compare_digest(expected, signature)


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

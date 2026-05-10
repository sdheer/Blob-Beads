"""
test_crypto.py — Unit tests for the AES-256-GCM encryption module.
"""

import base64
import os
import pytest
from cryptography.exceptions import InvalidTag

from mcp_temporal_vault.crypto import (
    decrypt_blob,
    encrypt_blob,
    get_vault_key,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def vault_key() -> bytes:
    """Returns a valid 32-byte key."""
    return os.urandom(32)


@pytest.fixture()
def vault_key_env(vault_key, monkeypatch):
    """Sets MCP_VAULT_KEY in the environment and returns the raw key bytes."""
    encoded = base64.urlsafe_b64encode(vault_key).decode()
    monkeypatch.setenv("MCP_VAULT_KEY", encoded)
    return vault_key


# ---------------------------------------------------------------------------
# get_vault_key
# ---------------------------------------------------------------------------

def test_get_vault_key_unset(monkeypatch, tmp_path):
    """When MCP_VAULT_KEY is not set, get_vault_key returns None."""
    monkeypatch.delenv("MCP_VAULT_KEY", raising=False)
    from mcp_temporal_vault.config import global_config
    monkeypatch.setattr(global_config, "vault_dir", tmp_path / ".mcp_vault")
    assert get_vault_key() is None


def test_get_vault_key_valid(vault_key_env, vault_key):
    """A properly encoded 32-byte key is returned correctly."""
    result = get_vault_key()
    assert result == vault_key


def test_get_vault_key_wrong_length(monkeypatch):
    """Keys that decode to != 32 bytes raise ValueError."""
    short = base64.urlsafe_b64encode(os.urandom(16)).decode()
    monkeypatch.setenv("MCP_VAULT_KEY", short)
    with pytest.raises(ValueError, match="32 bytes"):
        get_vault_key()


def test_get_vault_key_invalid_base64(monkeypatch):
    """Non-base64 values raise ValueError."""
    monkeypatch.setenv("MCP_VAULT_KEY", "not-valid-base64!!!")
    with pytest.raises(ValueError):
        get_vault_key()


# ---------------------------------------------------------------------------
# encrypt_blob / decrypt_blob round-trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip(vault_key):
    """Encrypting then decrypting a payload returns the original bytes."""
    plaintext = b"The quick brown fox jumps over the lazy dog"
    ciphertext = encrypt_blob(plaintext, vault_key)
    recovered = decrypt_blob(ciphertext, vault_key)
    assert recovered == plaintext


def test_encrypt_produces_different_ciphertexts(vault_key):
    """Each encrypt call uses a fresh random nonce → different ciphertext."""
    plaintext = b"same data"
    ct1 = encrypt_blob(plaintext, vault_key)
    ct2 = encrypt_blob(plaintext, vault_key)
    assert ct1 != ct2  # Nonces differ


def test_decrypt_tampered_ciphertext(vault_key):
    """Bit-flipping the ciphertext causes GCM tag verification to fail."""
    plaintext = b"sensitive blob content"
    ciphertext = bytearray(encrypt_blob(plaintext, vault_key))
    # Flip a byte in the ciphertext region (after 12-byte nonce)
    ciphertext[15] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_blob(bytes(ciphertext), vault_key)


def test_decrypt_tampered_tag(vault_key):
    """Tampering with the GCM tag raises InvalidTag."""
    plaintext = b"blob bytes"
    ciphertext = bytearray(encrypt_blob(plaintext, vault_key))
    # Flip the last byte (part of the 16-byte GCM tag)
    ciphertext[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_blob(bytes(ciphertext), vault_key)


def test_decrypt_wrong_key(vault_key):
    """Decrypting with a different key raises InvalidTag."""
    plaintext = b"secret"
    ciphertext = encrypt_blob(plaintext, vault_key)
    wrong_key = os.urandom(32)
    with pytest.raises(InvalidTag):
        decrypt_blob(ciphertext, wrong_key)


def test_decrypt_too_short(vault_key):
    """Input shorter than nonce + tag minimum raises ValueError."""
    with pytest.raises(ValueError, match="too short"):
        decrypt_blob(b"\x00" * 10, vault_key)

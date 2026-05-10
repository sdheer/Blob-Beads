"""
key_manager.py — Load the vault encryption key from a secure file.
"""

import base64
import os
from pathlib import Path
from typing import Optional

from mcp_temporal_vault.audit import audit
from mcp_temporal_vault.config import global_config

def _get_key_path() -> Path:
    return global_config.vault_dir / "key"

def _read_key_file() -> Optional[bytes]:
    """Read the raw 32-byte key from the file, if present."""
    key_path = _get_key_path()
    if not key_path.exists():
        return None
        
    # Ensure permissions are safe (0o600)
    st = key_path.stat()
    if (st.st_mode & 0o777) != 0o600:
        audit("KEY_PERM_INSECURE", {"path": str(key_path)})
        raise PermissionError(f"Vault key file must be mode 600: {key_path}")
        
    raw = key_path.read_text().strip()
    try:
        key = base64.urlsafe_b64decode(raw + "==")
    except Exception as exc:
        audit("KEY_MALFORMED", {"error": str(exc)})
        raise ValueError("Vault key file contains malformed base64.") from exc
        
    if len(key) != 32:
        raise ValueError("Vault key must decode to exactly 32 bytes.")
        
    return key

def get_vault_key() -> Optional[bytes]:
    """
    Public accessor used by crypto.py.
    Preference order:
      1. Environment variable `MCP_VAULT_KEY`
      2. File `~/.mcp_vault/key`
    Returns None if neither is set (encryption disabled).
    """
    env = os.getenv("MCP_VAULT_KEY")
    if env:
        try:
            key = base64.urlsafe_b64decode(env.strip() + "==")
        except Exception:
            audit("KEY_ENV_INVALID")
            raise ValueError("MCP_VAULT_KEY is malformed.") from None
            
        if len(key) != 32:
            raise ValueError("Vault key must decode to exactly 32 bytes.")
            
        audit("KEY_LOADED_ENV")
        return key
            
    key = _read_key_file()
    if key:
        audit("KEY_LOADED_FILE")
    return key

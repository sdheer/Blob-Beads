"""
audit.py — JSON-lines audit logger for security events.

The log lives under the vault directory and is chmod 600.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from mcp_temporal_vault.config import global_config

def _get_audit_log_path() -> Path:
    return global_config.vault_dir / "audit.log"

_logger = logging.getLogger("mcp_vault_audit")
_logger.setLevel(logging.INFO)
_handler = None

def _setup_logger():
    global _handler
    if _handler is not None:
        return
        
    audit_log = _get_audit_log_path()
    if not audit_log.parent.exists():
        audit_log.parent.mkdir(parents=True, exist_ok=True)
    if not audit_log.exists():
        audit_log.touch(mode=0o600)
    else:
        # Ensure secure permissions
        os.chmod(audit_log, 0o600)
        
    _handler = logging.FileHandler(audit_log, encoding="utf-8")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(_handler)

def audit(event: str, details: Dict[str, Any] | None = None) -> None:
    """Write a JSON-lines audit record."""
    _setup_logger()
    entry: Dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": event,
    }
    if details:
        entry.update(details)
    _logger.info(json.dumps(entry, separators=(",", ":")))

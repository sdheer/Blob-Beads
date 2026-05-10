# src/mcp_temporal_vault/quota.py
"""
Per‑project storage quota (default 1 GB) and garbage‑collector.
"""
import os
from pathlib import Path
from typing import Dict, Set

from .config import global_config
from .audit import audit
from .cas import list_all_blobs, delete_blob

MAX_PROJECT_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB


def _project_usage(project_id: str) -> int:
    """Return total size (bytes) of blobs referenced by a project."""
    # Walk through the project's JSONL file and sum the sizes of its blobs.
    # This is a simple O(N) scan; for large vaults you could cache it.
    from .beads import iter_beads_reverse

    total = 0
    for bead in iter_beads_reverse(project_id):
        for entry in bead.manifest.values():
            total += entry.size  # ManifestEntry now holds size (added in models)
    return total


def enforce_quota(project_id: str) -> None:
    """Raise an exception if the project exceeds its quota."""
    usage = _project_usage(project_id)
    if usage > MAX_PROJECT_BYTES:
        audit("QUOTA_EXCEEDED", {"project_id": project_id, "usage_bytes": usage})
        raise RuntimeError(
            f"Project {project_id} exceeds storage quota of 1 GB ({usage:,} bytes used)."
        )
    audit("QUOTA_OK", {"project_id": project_id, "usage_bytes": usage})


def gc_collect() -> None:
    """Delete blobs that are no longer referenced by any bead."""
    # Collect all digests referenced in any bead.
    from .beads import iter_beads_reverse, get_last_bead

    referenced: Set[str] = set()
    # Walk every project directory under the vault.
    for proj_dir in global_config.get_beads_dir().glob("*.jsonl"):
        project_id = proj_dir.stem
        for bead in iter_beads_reverse(project_id):
            referenced.update(bead.manifest.keys())

    # Delete everything not referenced.
    for digest in list_all_blobs():
        if digest not in referenced:
            delete_blob(digest)
            audit("GC_DELETED", {"digest": digest})

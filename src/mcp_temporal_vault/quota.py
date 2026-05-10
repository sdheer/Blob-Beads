"""
quota.py — Per-project storage quota and garbage collection.
"""

from pathlib import Path
from typing import Set

from mcp_temporal_vault.audit import audit
from mcp_temporal_vault.config import global_config

MAX_PROJECT_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB

def _project_usage(project_id: str) -> int:
    """Return total size (bytes) of blobs referenced by a project."""
    from mcp_temporal_vault.beads import iter_beads_reverse
    total = 0
    # Walk through the project's JSONL file and sum the sizes of its blobs.
    # Note: For large projects, this might need caching in the future.
    for bead in iter_beads_reverse(project_id):
        for entry in bead.manifest.values():
            total += getattr(entry, "size", 0)  # Handle backward compatibility
    return total

def enforce_quota(project_id: str) -> None:
    """Raise an exception if the project exceeds its quota."""
    usage = _project_usage(project_id)
    if usage > MAX_PROJECT_BYTES:
        audit("QUOTA_EXCEEDED", {"project_id": project_id, "usage_bytes": usage})
        raise RuntimeError(
            f"Project {project_id} exceeds storage quota of 1GB ({usage:,} bytes used)."
        )
    audit("QUOTA_OK", {"project_id": project_id, "usage_bytes": usage})

def gc_collect() -> None:
    """Delete blobs that are no longer referenced by any bead."""
    from mcp_temporal_vault.beads import iter_beads_reverse
    from mcp_temporal_vault.cas import _ENC_SUFFIX, _PLAIN_SUFFIX
    
    referenced: Set[str] = set()
    
    # Walk every project directory under the vault
    for proj_file in global_config.get_beads_dir().glob("*.jsonl"):
        project_id = proj_file.stem
        for bead in iter_beads_reverse(project_id):
            referenced.update(entry.sha256 for entry in bead.manifest.values())
            
    # Delete everything not referenced
    hashbucket = global_config.get_hashbucket_dir()
    for root_dir in hashbucket.iterdir():
        if not root_dir.is_dir():
            continue
        for blob_file in root_dir.iterdir():
            if not blob_file.is_file():
                continue
            
            # Extract digest from filename (remove suffix)
            name = blob_file.name
            if name.endswith(_ENC_SUFFIX):
                digest = name[:-len(_ENC_SUFFIX)]
            elif name.endswith(_PLAIN_SUFFIX):
                digest = name[:-len(_PLAIN_SUFFIX)]
            else:
                continue
                
            if digest not in referenced:
                blob_file.unlink()
                audit("GC_DELETED", {"digest": digest, "file": blob_file.name})

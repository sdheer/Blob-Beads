import fcntl
import json
import os
import time
from pathlib import Path
from typing import Iterator, Optional

from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.models import Bead

class BeadStorageError(Exception):
    pass

def _get_project_file(project_id: str) -> Path:
    return global_config.get_beads_dir() / f"{project_id}.jsonl"

def append_bead(bead: Bead) -> None:
    project_file = _get_project_file(bead.project_id)
    json_str = bead.model_dump_json() + "\n"
    
    timeout_ms = global_config.jsonl_lock_timeout_ms
    start_time = time.time()
    
    with open(project_file, "a", encoding="utf-8") as f:
        while True:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError):
                if (time.time() - start_time) * 1000 > timeout_ms:
                    raise BeadStorageError("JSONL_APPEND_ERROR")
                time.sleep(0.01)
                
        try:
            f.write(json_str)
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

def iter_beads_reverse(project_id: str) -> Iterator[Bead]:
    """Yields Beads from a project's jsonl file in reverse chronological order."""
    project_file = _get_project_file(project_id)
    if not project_file.exists():
        return
        
    with open(project_file, "rb") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        buffer_size = 8192
        buffer = b""
        
        while position > 0:
            read_size = min(buffer_size, position)
            position -= read_size
            f.seek(position)
            chunk = f.read(read_size)
            buffer = chunk + buffer
            
            lines = buffer.split(b"\n")
            if position > 0:
                buffer = lines[0]
                lines = lines[1:]
                
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    yield Bead.model_validate_json(line)
                except Exception:
                    pass

def find_bead(bead_id: str) -> Optional[Bead]:
    """Scans all projects to find a bead by ID (reverse chronological)."""
    for p in global_config.get_beads_dir().glob("*.jsonl"):
        project_id = p.stem
        for bead in iter_beads_reverse(project_id):
            if bead.bead_id == str(bead_id):
                return bead
    return None

def get_last_bead(project_id: str) -> Optional[Bead]:
    try:
        return next(iter_beads_reverse(project_id))
    except StopIteration:
        return None

import json
import os
from pathlib import Path
from typing import List

DEFAULT_VAULT_DIR = "~/.mcp_vault"
DEFAULT_ZSTD_LEVEL = 3
DEFAULT_MAX_FILE_SIZE_MB = 50
DEFAULT_JSONL_LOCK_TIMEOUT_MS = 500
DEFAULT_IGNORE_PATTERNS = [
    ".git/**",
    "node_modules/**",
    "__pycache__/**",
    "*.pyc",
    "dist/**",
    "build/**",
]

class Config:
    def __init__(self):
        self.vault_dir = Path(os.path.expanduser(DEFAULT_VAULT_DIR))
        self.zstd_level = DEFAULT_ZSTD_LEVEL
        self.max_file_size_mb = DEFAULT_MAX_FILE_SIZE_MB
        self.jsonl_lock_timeout_ms = DEFAULT_JSONL_LOCK_TIMEOUT_MS
        self.ignore_patterns = list(DEFAULT_IGNORE_PATTERNS)

        self._load_config_file()

    def _load_config_file(self):
        config_path = self.vault_dir / "config.json"
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                if "vault_dir" in data:
                    self.vault_dir = Path(os.path.expanduser(data["vault_dir"]))
                if "zstd_level" in data:
                    self.zstd_level = data["zstd_level"]
                if "max_file_size_mb" in data:
                    self.max_file_size_mb = data["max_file_size_mb"]
                if "jsonl_lock_timeout_ms" in data:
                    self.jsonl_lock_timeout_ms = data["jsonl_lock_timeout_ms"]
                if "ignore_patterns" in data:
                    self.ignore_patterns = data["ignore_patterns"]
            except Exception:
                pass # Ignore invalid config for now

    def get_beads_dir(self) -> Path:
        p = self.vault_dir / "beads"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_hashbucket_dir(self) -> Path:
        p = self.vault_dir / "hashbucket"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_staging_dir(self) -> Path:
        p = self.vault_dir / "staging"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def get_project_ignore_patterns(self, cwd: Path) -> List[str]:
        patterns = list(self.ignore_patterns)
        vaultignore = cwd / ".vaultignore"
        if vaultignore.exists():
            try:
                with open(vaultignore, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            patterns.append(line)
            except Exception:
                pass
        return patterns

global_config = Config()

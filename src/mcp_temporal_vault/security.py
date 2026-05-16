"""
security.py — Path safety, CWD fingerprinting, and injection scanning.
"""

import fnmatch
import hashlib
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mcp_temporal_vault.config import global_config
from mcp_temporal_vault.models import Bead, ManifestEntry


class SecurityError(Exception):
    pass


# ---------------------------------------------------------------------------
# Injection scanning
# ---------------------------------------------------------------------------

SCANNABLE_TYPES = {
    "text/plain", "text/markdown", "text/html",
    "text/xml", "application/json", "text/csv",
}

INJECTION_PATTERNS = [
    r"<\s*(SYSTEM|INST|SYS|HUMAN|ASSISTANT)\s*[>:]",  # XML-style role tags
    r"ignore (all |prior |previous |above )instructions",
    r"(disregard|forget) (your |all )?(previous |prior )?instructions",
    r"you are now",                                    # persona hijack
    r"exfiltrate|send to|POST to http",                # data exfil
]

WHITELIST = {
    "system", "admin", "root", "sudo", "kernel", "docker", "podman",
    "ssh", "ssh-key", "private", "secret", "token", "apikey", "password",
    "credential", "access_key", "session", "cookie", "jwt", "saml",
}

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def scan_for_injection(raw_bytes: bytes, mime_type: str) -> Optional[Tuple[str, str]]:
    """
    Scans decompressed text content for prompt-injection patterns.
    Returns (code, pattern_string) if found, None otherwise.
    Only applies to SCANNABLE_TYPES — source code is intentionally excluded.
    If the content contains any whitelisted words, it is not flagged.
    """
    if mime_type not in SCANNABLE_TYPES:
        return None
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
        
    text_lower = text.lower()
    for word in WHITELIST:
        if word in text_lower:
            return None
            
    for i, pattern in enumerate(COMPILED_PATTERNS):
        if pattern.search(text):
            return "SUSPICIOUS_CONTENT", INJECTION_PATTERNS[i]
    return None


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def assert_safe_path(base_dir: Path, rel_path: str) -> Path:
    """
    Resolves `rel_path` relative to `base_dir` and asserts the result
    is strictly inside `base_dir`.  Raises SecurityError('PATH_TRAVERSAL')
    for absolute paths or paths that escape the base via `..` components.
    """
    if os.path.isabs(rel_path):
        raise SecurityError("PATH_TRAVERSAL")
    target_path = (base_dir / rel_path).resolve()
    base_resolved = base_dir.resolve()
    try:
        target_path.relative_to(base_resolved)
    except ValueError:
        raise SecurityError("PATH_TRAVERSAL")
    return target_path


# ---------------------------------------------------------------------------
# Ignore-pattern matching (canonical implementation, used by both server
# and fingerprint_cwd to ensure consistent behaviour)
# ---------------------------------------------------------------------------

def is_ignored(rel_path: str, patterns: List[str]) -> bool:
    """
    Returns True if `rel_path` matches any of the gitignore-style `patterns`.
    Supports simple globs and a naïve `**` approximation.
    """
    basename = rel_path.split("/")[-1]
    for pattern in patterns:
        # Direct match against full relative path
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        # Check if any path component is matched (e.g. "node_modules/**")
        if fnmatch.fnmatch(rel_path + "/", pattern) or fnmatch.fnmatch(rel_path, pattern.rstrip("/")):
            return True
        # Naïve ** handling
        if "**" in pattern:
            base_pattern = pattern.replace("**", "*")
            if fnmatch.fnmatch(rel_path, base_pattern) or fnmatch.fnmatch(basename, base_pattern):
                return True
        # Directory prefix patterns (e.g. ".git/**" should match ".git/config")
        prefix = pattern.rstrip("/**").rstrip("/")
        if rel_path == prefix or rel_path.startswith(prefix + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# CWD fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_cwd(cwd: Path, target_manifest: Dict[str, ManifestEntry]) -> bool:
    """
    Return **True** if the working directory differs from the manifest.
    The vault directory itself is ignored, preventing a false‑positive dirty
    detection when the server runs inside the vault.
    """
    ignore_patterns = global_config.get_project_ignore_patterns(cwd)
    vault_root = global_config.vault_dir.resolve()
    def _in_vault(p: Path) -> bool:
        try:
            p.resolve().relative_to(vault_root)
            return True
        except ValueError:
            return False
    seen: set = set()
    for root, dirs, files in os.walk(cwd):
        # prune ignored dirs and vault dir
        dirs[:] = [
            d
            for d in dirs
            if not is_ignored(
                (Path(root) / d).relative_to(cwd).as_posix() + "/",
                ignore_patterns,
            )
            and not _in_vault(Path(root) / d)
        ]
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(cwd).as_posix()
            if is_ignored(rel_path, ignore_patterns):
                continue
            if _in_vault(file_path):
                continue
            seen.add(rel_path)
            if rel_path not in target_manifest:
                return True
            with open(file_path, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != target_manifest[rel_path].sha256:
                    return True
    # Deleted files?
    for path in target_manifest:
        if path not in seen:
            return True
    return False


def fingerprint_hybrid(cwd: Path, bead: Bead, repo_root: Optional[Path]) -> bool:
    """
    Return True if cwd is dirty vs target bead (CAS manifest and/or git snapshot).
    When bead.git_sha is set and repo_root is provided, expand expected paths with
    tracked files at that commit so trimmed manifests still fingerprint correctly.
    """
    if not bead.git_sha or repo_root is None:
        return fingerprint_cwd(cwd, bead.manifest)

    from mcp_temporal_vault.git_bridge import manifest_entry_at_commit, tracked_paths_at_commit

    expanded: Dict[str, ManifestEntry] = dict(bead.manifest)
    for rel_path in tracked_paths_at_commit(repo_root, bead.git_sha):
        if rel_path in expanded:
            continue
        entry = manifest_entry_at_commit(repo_root, bead.git_sha, rel_path)
        if entry is not None:
            expanded[rel_path] = entry
    return fingerprint_cwd(cwd, expanded)
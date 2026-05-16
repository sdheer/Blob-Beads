"""Tests for git_bridge helpers."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mcp_temporal_vault.git_bridge import (
    cwd_inside_git_repo,
    file_sha256_at_commit,
    find_git_root,
    get_head_sha,
    is_clean_worktree,
    manifest_paths_satisfied_by_git,
    tracked_paths_at_commit,
    trim_manifest_for_git,
)
from mcp_temporal_vault.models import ManifestEntry


pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not on PATH")


def _git(repo: Path, *args: str):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_find_git_root_nested(tmp_path):
    repo = tmp_path / "repo"
    sub = repo / "a" / "b"
    sub.mkdir(parents=True)
    _git(repo, "init")
    assert find_git_root(sub).resolve() == repo.resolve()


def test_find_git_root_missing(tmp_path):
    assert find_git_root(tmp_path / "nogit") is None


def test_head_and_clean(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@test")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("one")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-m", "m")
    sha = get_head_sha(repo)
    assert sha and len(sha) == 40
    assert is_clean_worktree(repo)

    (repo / "dirty.txt").write_text("x")
    assert not is_clean_worktree(repo)


def test_file_sha256_at_commit(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@test")
    _git(repo, "config", "user.name", "t")
    raw = b"\x00binary\xff"
    (repo / "b.bin").write_bytes(raw)
    _git(repo, "add", "b.bin")
    _git(repo, "commit", "-m", "m")
    sha = get_head_sha(repo)
    assert file_sha256_at_commit(repo, sha, "b.bin") == hashlib.sha256(raw).hexdigest()
    assert file_sha256_at_commit(repo, sha, "missing.txt") is None


def test_tracked_paths_at_commit(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@test")
    _git(repo, "config", "user.name", "t")
    (repo / "src").mkdir()
    (repo / "src/x.py").write_text("x")
    _git(repo, "add", "src/x.py")
    _git(repo, "commit", "-m", "m")
    sha = get_head_sha(repo)
    paths = tracked_paths_at_commit(repo, sha)
    assert "src/x.py" in paths


def test_manifest_paths_satisfied(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@test")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("hello")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-m", "m")
    sha = get_head_sha(repo)
    hx = hashlib.sha256(b"hello").hexdigest()
    manifest = {
        "a.txt": ManifestEntry(sha256=hx, mime_type="text/plain", size=5),
        "other.txt": ManifestEntry(sha256="a" * 64, mime_type="text/plain", size=1),
    }
    sat = manifest_paths_satisfied_by_git(repo, sha, manifest)
    assert sat == {"a.txt"}
    trimmed = trim_manifest_for_git(manifest, sat)
    assert list(trimmed.keys()) == ["other.txt"]


def test_cwd_inside_git_repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    sub = repo / "deep"
    sub.mkdir()
    _git(repo, "init")
    assert cwd_inside_git_repo(sub, repo)
    assert not cwd_inside_git_repo(tmp_path / "outside", repo)

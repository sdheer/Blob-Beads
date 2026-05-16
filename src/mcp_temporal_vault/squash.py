"""squash.py — semantic milestone squash with optional git-linked manifest trimming."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Dict, List

from mcp_temporal_vault.beads import iter_beads_forward, rewrite_project_beads
from mcp_temporal_vault.crypto import sign_manifest
from mcp_temporal_vault.git_bridge import (
    cwd_inside_git_repo,
    find_git_root,
    manifest_paths_satisfied_by_git,
    trim_manifest_for_git,
)
from mcp_temporal_vault.models import Bead, StepType


class SquashError(Exception):
    """Logical error during squash (carry machine-readable code)."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _merge_strings_preserving_order(groups: List[List[str]]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for g in groups:
        for s in g:
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


def squash_milestone_range(
    project_id: str,
    first_bead_id: str,
    last_bead_id: str,
    milestone_summary: str,
    cwd: Path,
    key: bytes,
    prune_git_blobs: bool = False,
    step_type: StepType = "milestone",
) -> Dict[str, object]:
    """
    Replace beads[first..last] inclusive (JSONL order) with one milestone bead.
    Optional pruning drops manifest paths reproducible from git at bead.git_sha.
    """
    beads = list(iter_beads_forward(project_id))
    if not beads:
        raise SquashError("EMPTY_PROJECT", "No beads for this project")

    id_to_idx = {b.bead_id: i for i, b in enumerate(beads)}
    if first_bead_id not in id_to_idx:
        raise SquashError("BEAD_NOT_FOUND", f"first_bead_id not found: {first_bead_id}")
    if last_bead_id not in id_to_idx:
        raise SquashError("BEAD_NOT_FOUND", f"last_bead_id not found: {last_bead_id}")

    i = id_to_idx[first_bead_id]
    j = id_to_idx[last_bead_id]
    if i > j:
        raise SquashError(
            "INVALID_RANGE",
            "first_bead_id must not come after last_bead_id in timeline order",
        )

    dropped = beads[i : j + 1]
    tip = dropped[-1]

    merged_decisions = _merge_strings_preserving_order([b.decisions for b in dropped])
    merged_todos = _merge_strings_preserving_order([b.todos for b in dropped])

    milestone_id = str(uuid.uuid4())
    manifest_before = len(tip.manifest)
    pruned_paths = 0

    new_manifest = dict(tip.manifest)
    git_sha_out = tip.git_sha

    repo_root = find_git_root(cwd.resolve())
    if (
        prune_git_blobs
        and git_sha_out
        and repo_root is not None
        and cwd_inside_git_repo(cwd.resolve(), repo_root)
    ):
        satisfied = manifest_paths_satisfied_by_git(repo_root, git_sha_out, new_manifest)
        pruned_paths = len(satisfied)
        new_manifest = trim_manifest_for_git(new_manifest, satisfied)

    signature = sign_manifest(new_manifest, key, git_sha_out)

    milestone = Bead(
        bead_id=milestone_id,
        project_id=project_id,
        parent_id=beads[i - 1].bead_id if i > 0 else None,
        timestamp=int(time.time()),
        step_type=step_type,
        summary=milestone_summary,
        decisions=merged_decisions,
        todos=merged_todos,
        manifest=new_manifest,
        manifest_signature=signature,
        git_sha=git_sha_out,
    )

    prefix = beads[:i]
    suffix = beads[j + 1 :]
    if suffix:
        head = suffix[0].model_copy(update={"parent_id": milestone_id})
        suffix = [head] + list(suffix[1:])

    rewrite_project_beads(project_id, prefix + [milestone] + suffix)

    return {
        "milestone_bead_id": milestone_id,
        "beads_removed": len(dropped),
        "manifest_entries_before": manifest_before,
        "manifest_entries_after": len(new_manifest),
        "pruned_git_paths": pruned_paths,
    }

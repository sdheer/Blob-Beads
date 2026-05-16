from pydantic import BaseModel, Field, field_validator
from typing import Dict, List, Literal, Optional
import re

StepType = Literal["checkpoint", "decision", "observation", "todo_update", "milestone"]
SaveStepType = Literal["checkpoint", "decision", "observation", "todo_update"]

_GIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")

# Allowed characters for project_id — prevents path traversal via filename
_PROJECT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')

class ManifestEntry(BaseModel):
    sha256: str
    mime_type: str
    size: int = 0  # Size in bytes, default 0 for backwards compatibility

class Bead(BaseModel):
    bead_id: str
    project_id: str
    parent_id: Optional[str]
    timestamp: int
    step_type: StepType
    summary: str
    decisions: List[str] = Field(default_factory=list)
    todos: List[str] = Field(default_factory=list)
    manifest: Dict[str, ManifestEntry] = Field(default_factory=dict)
    manifest_signature: Optional[str] = None  # HMAC-SHA256 signature to prevent tampering
    git_sha: Optional[str] = None  # HEAD when snapshot taken on clean git worktree (SHA-1 hex)

    @field_validator("git_sha")
    @classmethod
    def validate_git_sha(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not _GIT_SHA1_RE.match(v.lower()):
            raise ValueError("git_sha must be a 40-character lowercase hex SHA-1 commit id")
        return v.lower()

class SaveStateInput(BaseModel):
    project_id: str = Field(..., max_length=128)
    summary: str = Field(..., max_length=4096)
    step_type: SaveStepType = Field(default="checkpoint")
    decisions: List[str] = Field(default_factory=list)
    todos: List[str] = Field(default_factory=list)

    model_config = {"str_strip_whitespace": True}

    @classmethod
    def validate_project_id(cls, v: str) -> str:
        if not _PROJECT_ID_RE.match(v):
            raise ValueError(
                "project_id may only contain letters, digits, hyphens, and underscores"
            )
        return v

    def model_post_init(self, __context) -> None:
        if not _PROJECT_ID_RE.match(self.project_id):
            raise ValueError(
                "project_id may only contain letters, digits, hyphens, and underscores"
            )

class CheckoutStateInput(BaseModel):
    bead_id: str
    force: bool = False

class GetSummaryDeltaInput(BaseModel):
    bead_a: str
    bead_b: str


class SquashMilestoneInput(BaseModel):
    project_id: str = Field(..., max_length=128)
    first_bead_id: str
    last_bead_id: str
    milestone_summary: str = Field(..., max_length=8192)
    prune_git_blobs: bool = False
    step_type: StepType = Field(default="milestone")

    model_config = {"str_strip_whitespace": True}

    def model_post_init(self, __context) -> None:
        if not _PROJECT_ID_RE.match(self.project_id):
            raise ValueError(
                "project_id may only contain letters, digits, hyphens, and underscores"
            )

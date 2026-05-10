# mcp-temporal-vault — Technical Specification
**Version:** 2.1.0 | **Status:** Draft | **Target Platform:** ASUS Laptop (Local)

> **v2.0 Change Summary:** Replaced the monolithic `states` SQLite table with two decoupled storage primitives — **Beads** (JSONL append log for reasoning steps) and **Blobs** (binary hashbucket for filesystem state). They are linked exclusively via SHA-256 hashes embedded in Bead metadata.

> **v2.1 Change Summary:** Hardened the restore pipeline against blob tampering, decompression bombs, and prompt injection via restored file content. Added `mime_type` to the manifest schema. Expanded §10 Security & Safety from a summary table into fully specified mitigations with implementation code.

---

## 1. Overview

`mcp-temporal-vault` is a locally-hosted Model Context Protocol (MCP) server that implements a two-tier storage system for long-horizon coding context:

| Primitive | Format | Purpose | Written when |
|---|---|---|---|
| **Bead** | JSONL (one line per record) | Reasoning step metadata, decisions, todos, and a manifest of SHA-256 pointers | Every reasoning step |
| **Blob** | Binary (zstd-compressed) | Actual file content, content-addressed by SHA-256 | Every filesystem state change |

The two primitives are **decoupled by design**. A Bead never contains file bytes — it only holds hashes. A Blob never contains reasoning context — it is a pure content store. The SHA-256 hash is the sole join key between them.

**Scope:** Global to the machine. A single vault directory tracks state across all projects.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client (Agent)                     │
│           save_state / checkout_state / get_delta           │
└──────────────────────────────┬──────────────────────────────┘
                               │ MCP Protocol (stdio)
┌──────────────────────────────▼──────────────────────────────┐
│                   mcp-temporal-vault Server                  │
│                                                             │
│  ┌─────────────────┐   ┌──────────────────────────────────┐ │
│  │   Tool Layer    │   │           CAS Engine             │ │
│  │   (handlers)    │──▶│  scan → zstd → SHA-256 → route  │ │
│  └─────────────────┘   └──────────┬──────────────┬────────┘ │
└─────────────────────────────────  │  ────────────│──────────┘
                                    │              │
                     JSONL write    │              │  Binary push
                                    ▼              ▼
┌────────────────────────────┐   ┌─────────────────────────────┐
│  ~/.mcp_vault/beads/       │   │  ~/.mcp_vault/hashbucket/   │
│                            │   │                             │
│  {project_id}.jsonl        │   │  ab/abcdef1234...5678.zst   │
│  ─────────────────         │   │  f3/f3a0912b...cdef.zst     │
│  { bead_id, manifest:      │   │  ...                        │
│    { "src/a.py": SHA-256 ──┼───┼──▶ blob file }             │
│    ...                }    │   │                             │
│  { bead_id, manifest: ...} │   │  (keyed by SHA-256 prefix)  │
└────────────────────────────┘   └─────────────────────────────┘
          Append-only                 Content-Addressable Store
```

### 2.1 Storage Layout on Disk

```
~/.mcp_vault/
├── config.json                      # Server configuration
├── beads/
│   ├── {project_id}.jsonl           # One file per project; append-only
│   └── ...
└── hashbucket/
    ├── {sha256[0:2]}/               # Two-char prefix sharding (256 buckets)
    │   └── {full_sha256}.zst        # zstd-compressed file content
    └── ...
```

The hashbucket uses two-character directory sharding to avoid filesystem inode limits on directories with large numbers of files.

---

## 3. Data Model

### 3.1 Bead (JSONL Record)

A **Bead** is a single JSON object written as one line (no internal newlines) to the project's `.jsonl` file. Every reasoning step produces exactly one Bead. Beads are **never mutated** after being written; the file is append-only.

**Schema**

```typescript
type Bead = {
  // Identity
  bead_id:    string;         // UUID v4 — primary key for this reasoning step
  project_id: string;         // Project name (e.g., "banking-api")
  parent_id:  string | null;  // UUID v4 of the preceding Bead; null for root

  // Timing
  timestamp:  number;         // Unix epoch (seconds)

  // Reasoning context (human/agent-readable)
  step_type:  "checkpoint" | "decision" | "observation" | "todo_update";
  summary:    string;         // Semantic description of this step (max 4096 chars)
  decisions:  string[];       // Architectural or logic decisions made at this step
  todos:      string[];       // Active pending tasks as of this step

  // Filesystem pointer (links to Blobs via SHA-256)
  manifest:   Record<string, ManifestEntry>;
  // ^ { "relative/path/to/file": { sha256: "<hex>", mime_type: "<type>" } }
  //   Empty object ({}) if this step produced no filesystem change.
};

type ManifestEntry = {
  sha256:    string;   // hex-encoded SHA-256 of the compressed blob
  mime_type: string;   // MIME type detected at save time (e.g. "text/x-python", "application/octet-stream")
                       // Used on restore to gate injection scanning and agent context ingestion.
};
```

**Example Bead (single line in `.jsonl`):**

```json
{"bead_id":"a3f1...","project_id":"banking-api","parent_id":"9c2b...","timestamp":1718000000,"step_type":"checkpoint","summary":"Implemented JWT middleware with refresh token rotation","decisions":["Store refresh tokens in Redis, not DB, to allow instant revocation","Use RS256 not HS256 for stateless verification across services"],"todos":["Add rate-limiting to /auth/refresh","Write integration tests for token expiry edge cases"],"manifest":{"src/middleware/auth.py":{"sha256":"e3b0c44298fc1c14...","mime_type":"text/x-python"},"src/config.py":{"sha256":"6b86b273ff34fce1...","mime_type":"text/x-python"},"README.md":{"sha256":"a948904f2f0f479b...","mime_type":"text/markdown"}}}
```

### 3.2 Blob (Binary Hashbucket Entry)

A **Blob** is the zstd-compressed raw bytes of a single file, stored at a path derived entirely from its SHA-256 hash. Blobs have **no metadata of their own** — all context lives in the Bead manifest that references them.

**Storage path:** `~/.mcp_vault/hashbucket/{sha256[0:2]}/{sha256}.zst`

**Properties:**
- Keyed by content hash → identical file content stored exactly once globally, across all projects.
- Immutable after write — a hash collision is treated as a vault corruption error.
- Filename extension `.zst` signals the compression format for external tooling.

### 3.3 The SHA-256 Link

```
Bead.manifest["src/auth.py"].sha256  ──▶  "e3b0c44298fc1c149afb..."
                                                      │
                           hashbucket path derivation │
                                                      ▼
                     ~/.mcp_vault/hashbucket/e3/e3b0c44298fc1c149afb....zst
```

A Bead's `manifest` is the **only** place that associates a file path with a hash. The hashbucket has no knowledge of paths. Path resolution always requires reading a Bead first.

---

## 4. Write & Read Pipelines

### 4.1 Save Pipeline (Reasoning Step → Bead + Blobs)

```
Agent calls save_state
        │
        ▼
[1] Scan CWD
    │   Skip: .git/, node_modules/, __pycache__/, .vaultignore patterns
    │   Skip: files > max_file_size_mb
    │
    ▼
[2] For each file:
    │
    ├── Read raw bytes
    │
    ├── [zstd compress, level 3]
    │         │
    │         ▼
    │   Compressed bytes
    │         │
    │         ├── [SHA-256 hash]  ─────────────────────────────────┐
    │         │                                                     │
    │         ▼                                                     │
    │   blob_path = hashbucket/{sha256[:2]}/{sha256}.zst            │
    │         │                                                     │
    │   EXISTS on disk?                                             │
    │   ├── YES → skip write (deduplication)                       │
    │   └── NO  → write .zst file atomically (tmp → rename)        │
    │                                                               │
    └── append  "relative/path" → { sha256, mime_type }  to manifest ────┘
        (mime_type detected via python-magic or mimetypes stdlib;
         building Bead.manifest incrementally)
        │
        ▼
[3] Construct Bead object
    { bead_id: new UUID, parent_id: last_bead_id, manifest,
      summary, decisions, todos, step_type, timestamp: now() }
        │
        ▼
[4] Validate Bead with Pydantic schema
        │
        ▼
[5] Append single JSON line to beads/{project_id}.jsonl
    (acquire fcntl.flock; write; fsync; release lock)
        │
        ▼
[6] Return bead_id to agent
```

**Atomicity:** Blob files are written via a temp file + `os.rename()` within the same filesystem, making individual blob writes atomic. The JSONL append acquires an advisory file lock (`fcntl.flock`) before writing to prevent corruption under concurrent access.

### 4.2 Restore Pipeline (Bead → Filesystem)

```
Agent calls checkout_state(bead_id)
        │
        ▼
[1] Reverse-scan beads/{project_id}.jsonl from EOF
    Find the line where bead_id matches
        │
        ▼
[2] Parse Bead; extract manifest: { path → { sha256, mime_type } }
        │
        ▼
[3] Safety check: fingerprint CWD against current manifest
    If untracked changes detected → return DIRTY_WORKING_DIR
    (agent must save_state first, or pass force=true)
        │
        ▼
[4] Remove tracked files absent from target manifest
        │
        ▼
[5] For each (path, { sha256, mime_type }) in manifest:
    │
    ├── Assert path is relative and within CWD → else PATH_TRAVERSAL
    │
    ├── blob_path = hashbucket/{sha256[:2]}/{sha256}.zst
    │
    ├── [stream-decompress with byte cap]
    │     decompressor = ZstdDecompressor()
    │     raw_bytes = decompressor.stream_reader(fh).read(max_bytes + 1)
    │     if len(raw_bytes) > max_bytes → raise BLOB_TOO_LARGE
    │
    ├── [integrity check]                          ← NEW
    │     actual = hashlib.sha256(raw_bytes).hexdigest()
    │     if actual != sha256 → raise BLOB_INTEGRITY_FAILURE
    │     (detects hashbucket tampering by any process with fs access)
    │
    ├── [injection scan — text-type files only]    ← NEW
    │     if mime_type in SCANNABLE_TYPES:          # text/*, application/json, etc.
    │       if matches injection_patterns(raw_bytes):
    │         emit SUSPICIOUS_CONTENT warning in tool response
    │         (non-blocking; write proceeds; agent decides how to handle)
    │
    └── [write raw bytes to path; mkdir -p as needed]
        │
        ▼
[6] Return { restored_bead_id, files_written, files_removed, warnings[] }
```

**Injection pattern scanning:** The server maintains a configurable list of regex patterns applied to decompressed text content before writing. Default patterns target common prompt-injection signatures in non-code files:

```python
INJECTION_PATTERNS = [
    r"<\s*(SYSTEM|INST|SYS|HUMAN|ASSISTANT)\s*[>:]",   # XML-style role tags
    r"ignore (all |prior |previous |above )instructions",
    r"(disregard|forget) (your |all )?(previous |prior )?instructions",
    r"you are now",                                      # persona hijack
    r"exfiltrate|send to|POST to http",                  # data exfil
]

SCANNABLE_TYPES = {
    "text/plain", "text/markdown", "text/html",
    "text/xml",   "application/json", "text/csv",
}
# Explicitly excluded: text/x-python, text/javascript, etc.
# Source code files are not scanned — false-positive rate too high
# (legitimate code contains strings matching any heuristic).
```

The scan result is a **warning**, not a block. The tool response always includes a `warnings` list; the agent is responsible for deciding whether to read a flagged file into its context window.

### 4.3 Deduplication Properties

| Scenario | Blob writes | Bead writes |
|---|---|---|
| Same file, same content, different project | 0 new blobs | 1 new Bead |
| Same file, renamed | 0 new blobs | 1 new Bead (new manifest key) |
| File content changed by 1 byte | 1 new blob | 1 new Bead |
| No filesystem change (reasoning-only step) | 0 new blobs | 1 new Bead (empty manifest `{}`) |

---

## 5. Tool Definitions

All tools are exposed over the MCP protocol. Input is schema-validated (Pydantic v2); invalid inputs return a structured `MCPError` and never touch the filesystem.

---

### `save_state`

Writes a Bead (JSONL) capturing the current reasoning step and pushes any new file-content Blobs to the hashbucket.

**Input**

```python
class SaveStateInput(BaseModel):
    project_id: str       = Field(..., max_length=128)
    summary:    str       = Field(..., max_length=4096)
    step_type:  StepType  = Field(default="checkpoint")
    decisions:  list[str] = Field(default_factory=list)
    todos:      list[str] = Field(default_factory=list)
    # parent_id injected automatically from the last known bead for this project
```

**Behaviour:** Run Save Pipeline (§4.1); return new `bead_id`.

**Output**

```python
{ "bead_id": str }   # UUID v4
```

**Error codes**

| Code | Condition |
|---|---|
| `INVALID_INPUT` | Pydantic validation failure |
| `FS_READ_ERROR` | File unreadable during CWD scan |
| `BLOB_WRITE_ERROR` | Hashbucket write failure (disk full, permissions) |
| `JSONL_APPEND_ERROR` | Failed to append Bead line (lock timeout, I/O error) |

---

### `list_states`

Streams Bead headers from the JSONL log without reading any blob content.

**Input**

```python
{ "project_id": str | None }   # Omit to list all projects
```

**Output**

```python
list[{
    "bead_id":    str,
    "parent_id":  str | None,
    "timestamp":  int,
    "step_type":  str,
    "summary":    str,
    "file_count": int    # len(bead.manifest)
}]
```

Ordered by `timestamp DESC`. Reads the JSONL file from EOF backward using a reverse-line iterator to avoid loading the full history into memory. Maximum 200 records per response.

---

### `checkout_state`

Restores the working directory to the exact filesystem state recorded in a given Bead. **Destructive.**

**Input**

```python
class CheckoutStateInput(BaseModel):
    bead_id: UUID
    force:   bool = False   # Bypass dirty-working-dir check
```

**Behaviour:** Run Restore Pipeline (§4.2).

**Output**

```python
{
    "restored_bead_id": str,
    "files_written":    int,
    "files_removed":    int,
    "warnings": list[{          # Non-empty if injection scan flagged any files
        "path":    str,
        "code":    str,         # e.g. "SUSPICIOUS_CONTENT"
        "detail":  str          # Which pattern matched
    }]
}
```

**Error codes**

| Code | Condition |
|---|---|
| `BEAD_NOT_FOUND` | No line in JSONL matches `bead_id` |
| `BLOB_MISSING` | A SHA-256 in the manifest has no corresponding `.zst` in hashbucket (vault corruption) |
| `BLOB_INTEGRITY_FAILURE` | Decompressed bytes hash does not match the manifest SHA-256 (tampering detected) |
| `BLOB_TOO_LARGE` | Decompressed size exceeds `max_file_size_mb` (decompression bomb guard) |
| `DIRTY_WORKING_DIR` | CWD has untracked changes; `force` not set |
| `PATH_TRAVERSAL` | A manifest path resolves outside CWD (security rejection) |

---

### `get_summary_delta`

Returns the semantic and structural delta between two Beads. No blobs are read; no files are written.

**Input**

```python
{
    "bead_a": UUID,   # "before" state
    "bead_b": UUID    # "after" state
}
```

**Behaviour**

1. Parse both Beads from their respective JSONL files (bead_id is globally unique; may span projects).
2. Diff `decisions` lists: entries added and removed.
3. Diff `todos` lists: resolved (in A, absent in B) and added (in B, absent in A).
4. Diff `manifest` dicts: added paths, removed paths, modified paths (same path, different SHA-256).

**Output**

```python
{
    "summary_a": str,
    "summary_b": str,
    "decisions": { "added": list[str], "removed": list[str] },
    "todos":     { "resolved": list[str], "added": list[str] },
    "files": {
        "added":     list[str],   # paths new in bead_b
        "removed":   list[str],   # paths absent in bead_b
        "modified":  list[str],   # same path, hash changed
        "unchanged": int          # count only; paths omitted for brevity
    }
}
```

---

## 6. Implementation Stack

| Component | Choice | Rationale |
|---|---|---|
| **MCP SDK** | Python (`mcp` PyPI) | Preferred for GIS/ArcPy project compatibility |
| **Schema validation** | Pydantic v2 | Write-boundary enforcement for Beads and tool inputs |
| **Bead storage** | JSONL flat files (`beads/`) | Append-only, human-readable, streamable, zero DB dependency |
| **Blob storage** | Filesystem hashbucket (`hashbucket/`) | Directly addressable by hash; no query needed for CAS lookup |
| **Compression** | `zstandard` (PyPI) | Level 3; ~3–5× ratio on source code; fast decompression |
| **Hashing** | `hashlib.sha256` (stdlib) | Deterministic CAS key; no dependency |
| **MIME detection** | `python-magic` (PyPI) | Libmagic bindings; used at save time to populate `mime_type` in manifest; gates injection scan on restore |
| **Serialization** | `json` (stdlib) | Beads are plain JSON lines; `json.dumps()` is mandatory (never manual string concat) to guarantee `\n` escaping |
| **Transport** | `stdio` | Standard for local MCP servers |

> **Note on SQLite removal:** The v1.0 `vault.db` SQLite database is no longer used. JSONL and filesystem CAS are sufficient for all current operations and eliminate the write-transaction overhead on every save.

### 6.1 Python Package Dependencies

```toml
# pyproject.toml
[project]
dependencies = [
  "mcp>=1.0.0",
  "pydantic>=2.0.0",
  "zstandard>=0.22.0",
  # stdlib only beyond this point: json, hashlib, uuid, os, pathlib, fcntl
]
```

---

## 7. Configuration

The server reads `~/.mcp_vault/config.json` on startup. All fields are optional with defaults shown.

```jsonc
{
  "vault_dir":             "~/.mcp_vault",  // Root for beads/ and hashbucket/
  "zstd_level":            3,               // 1 (fast) – 22 (max)
  "max_file_size_mb":      50,              // Files larger than this are excluded
  "jsonl_lock_timeout_ms": 500,             // Max wait for JSONL append lock
  "ignore_patterns": [
    ".git/**",
    "node_modules/**",
    "__pycache__/**",
    "*.pyc",
    "dist/**",
    "build/**"
  ]
}
```

A `.vaultignore` file in the project root (`.gitignore` syntax) appends to `ignore_patterns` for that directory only.

---

## 8. MCP Server Registration

```json
{
  "mcpServers": {
    "temporal-vault": {
      "command": "python",
      "args": ["-m", "mcp_temporal_vault"],
      "transport": "stdio"
    }
  }
}
```

---

## 9. Error Handling Contract

All tool errors return a structured object. The server never panics on a tool call.

```python
{
    "error": {
        "code":    str,   # Machine-readable constant
        "message": str,   # Human-readable description
        "detail":  Any    # Optional: affected paths, validation errors, etc.
    }
}
```

---

## 10. Security & Safety

| Risk | Mitigation |
|---|---|
| `checkout_state` overwrites CWD unintentionally | Dirty-working-dir fingerprint check; `force=true` required to bypass |
| Path traversal in Bead manifest | Each restored path is resolved and asserted to be within CWD before any write; rejected with `PATH_TRAVERSAL` |
| Hashbucket grows unbounded | Future: `gc_blobs` scans all JSONL files, builds live SHA-256 reference set, deletes unreferenced `.zst` files |
| JSONL corruption from concurrent writes | `fcntl.flock` advisory lock on append; timeout surfaced as `JSONL_APPEND_ERROR` |
| Hash collision (SHA-256) | Detected on blob write: if `{sha256}.zst` exists and decompressed bytes differ, raise `BLOB_COLLISION` and halt |

---

## 11. Migration from v1.0

v1.0 stored state in `vault.db` (SQLite) with a `states` table and a `blobs` table. v2.0 replaces both:

| v1.0 | v2.0 | Notes |
|---|---|---|
| `states` table row | Bead (JSONL line) | Fields map 1:1; `files_manifest` moves from msgpack BLOB column to inline JSON in Bead |
| `blobs` table row | `.zst` file in hashbucket | Same content and hash; storage moves from SQLite to filesystem |
| `vault.db` | `beads/` + `hashbucket/` | Old DB can be migrated with a one-time script (not in scope for v2.0) |

---

## 12. Future Extensions

- **`query_aggregate_memory`** — Full-text or vector search across Bead `summary` fields using SQLite FTS5 (imported only at query time) or an embedded vector store. Returns matching Bead summaries without injecting file content into context.
- **`gc_blobs`** — Walk all `.jsonl` files, build the live SHA-256 reference set, delete unreferenced `.zst` files from the hashbucket.
- **Branch support** — Allow non-linear Bead graphs (multiple children per `parent_id`) to model divergent experiment branches.
- **Remote sync** — Rsync `beads/` and `hashbucket/` to a remote host; JSONL and flat files are trivially rsync-friendly.

# mcp-temporal-vault

A locally-hosted Model Context Protocol (MCP) server that implements a two-tier storage system for long-horizon coding context, complete with built-in encryption, content-based deduplication, and garbage collection.

## Setup & Installation

1. Create a virtual environment and install the package:
```bash
python -m venv venv
source venv/bin/activate
pip install -e .
```

## Security & Encryption Setup

The vault uses AES-256-GCM encryption. The MCP server **requires** a configured key: every tool call fails with `MISSING_ENCRYPTION_KEY` until you set **`MCP_VAULT_KEY`** or create **`~/.mcp_vault/key`** as below (the process may still launch; tools stay blocked until the key exists).

1. Create the secure vault directory:
```bash
mkdir -p ~/.mcp_vault
chmod 700 ~/.mcp_vault
```

2. Generate a 32-byte Base64-encoded key and save it to the secure file:
```bash
python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" > ~/.mcp_vault/key
chmod 600 ~/.mcp_vault/key
```
*(The server strictly verifies that this key file is locked down to `600` permissions).*

## Adding to an MCP Client

To use the vault with an MCP-compliant client (e.g., Claude Desktop, VS Code, Cursor), you need to add it to your `mcp.json` (or `claude_desktop_config.json`) configuration file.

Since the server relies on your local Python environment, you must provide the **absolute path** to the python executable inside your `venv`.

Add the following entry to your configuration:

```json
{
  "mcpServers": {
    "temporal-vault": {
      "command": "/ABSOLUTE/PATH/TO/Blob-Beads/venv/bin/python",
      "args": [
        "-m",
        "mcp_temporal_vault"
      ],
      "env": {}
    }
  }
}
```

*Be sure to replace `/ABSOLUTE/PATH/TO/Blob-Beads/` with the actual path to where you cloned this repository.*

## Ignoring Files (.vaultignore)

To prevent bloating the vault with build artifacts, dependencies, and cache files, you can create a `.vaultignore` file in the root of your project. This file works similarly to a `.gitignore`.

Common patterns to include in your `.vaultignore`:

```text
# Exclude build outputs and caches
bin/
obj/
node_modules/
.vs/
*.dll
*.pdb
*.cache
*.deps.json
*.assets.json
```

The server automatically applies these patterns whenever you call `save_state` or `get_summary_delta`.

## Storage Quota

Each project has a default storage quota of **1 GB**. This limit applies to the total size of unique blobs referenced by the project's beads. 

- If a project exceeds this limit, `save_state` will fail with a `QUOTA_EXCEEDED` error.
- Use the **`gc_collect`** MCP tool to delete blobs that are no longer referenced by any bead manifest across **all** projects (same logic as `mcp_temporal_vault.quota.gc_collect()`).

## Semantic squash and git-linked pruning

On **`save_state`**, if the workspace is inside a **clean** Git repo (empty `git status --porcelain`), the bead stores **`git_sha`** (40-character commit SHA-1). Dirty trees omit **`git_sha`** so pruning is never inferred incorrectly.

The **`squash_milestone`** tool replaces an inclusive chronological range **`first_bead_id` … `last_bead_id`** with one **`milestone`** bead: merged **`decisions`** / **`todos`**, manifest from the **tip** bead of that range, and manifest signatures recomputed (HMAC includes optional **`git_sha`**).

If **`prune_git_blobs`** is true and the tip bead has **`git_sha`**, manifest paths whose CAS hashes match **`git show <git_sha>:path`** are dropped; **`gc_collect`** runs afterward so orphan blobs can be removed.

**`checkout_state`** runs **`git checkout --force <git_sha>`** at the repo root when **`git_sha`** is set, then restores remaining **CAS-only** manifest entries. Dirty-directory detection uses **`fingerprint_hybrid`** (CAS manifest plus tracked git paths at that commit).

Requirements:

- **`git`** on `PATH` for git-linked behavior (squash prune and hybrid checkout).
- Keeping the **vault directory outside** your Git checkout avoids spurious dirty status from untracked vault files.

Without Git, **`git_sha`** stays unset, pruning does not trim the manifest, and checkout stays CAS-only.

## Testing

```bash
# Install dev dependencies if you haven't already
pip install -e .[dev]

# Run the test suite
pytest tests/ -v
```

## Audit Logging

All security-relevant actions (saving blobs, encryption, path fingerprinting, and prompt-injection detection) are automatically logged in JSON-lines format at `~/.mcp_vault/audit.log`.

## Temporal Vault Agent Rules - add to your IDE
Use MCP temporal-vault tools to maintain work history and understand project evolution:
- **Orientation:** Always call `list_states` when joining a project to read recent summaries, decisions, and todos to quickly regain context.
- **Investigation:** Before fixing bugs or editing unfamiliar code, use `get_summary_delta` between a working and broken state (found via `list_states`) to pinpoint exactly which files were modified.
- **Safety Checkpoints:** Call `save_state` before making major refactors or risky changes.
- **Reversion:** Call `checkout_state` to immediately revert to a known good state if a coding experiment fails.
- **Documentation:** Write highly descriptive summaries when saving states.

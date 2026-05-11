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

The vault uses AES-256-GCM encryption. The server **will refuse to start** until an encryption key is generated and stored securely.

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

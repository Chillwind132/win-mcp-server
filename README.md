# win-mcp-server

[![License: MIT](https://img.shields.io/github/license/Chillwind132/win-mcp-server)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)

Remote Windows operations via WinRM/NTLM, exposed as an MCP (Model Context Protocol) server. Connects to any AD-joined Windows host using per-user credentials elicited at runtime — passwords live only in server memory with an idle TTL and are never logged.

- **40+ tools** — filesystem, services, registry, event logs, certificates, processes, network, scheduled tasks, and more
- **Per-user AD identity** — each request carries an `X-AD-User` header; the password is either supplied via the optional `X-AD-Password` header (no prompt) or elicited once and cached in-memory
- **Zero secrets on disk** — no credentials in config files, env vars, or logs

## Quick Start

```bash
docker compose -f docker-compose.yml -p win-mcp up -d --build --force-recreate
```

## Cursor `mcp.json`

```json
{
  "mcpServers": {
    "win-mcp": {
      "type": "http",
      "url": "http://localhost:8005/mcp",
      "headers": {
        "X-AD-User": "<your-ad-username>",
        "X-AD-Password": "<your-ad-password>"
      }
    }
  }
}
```

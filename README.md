# win-mcp-server

Remote Windows operations via WinRM/NTLM, exposed as an MCP (Model Context Protocol) server. Connects to any AD-joined Windows host using per-user credentials elicited at runtime — passwords live only in server memory with an idle TTL and are never logged.

- **40+ tools** — filesystem, services, registry, event logs, certificates, processes, network, scheduled tasks, and more
- **Per-user AD identity** — each request carries an `X-AD-User` header; passwords are prompted once and cached in-memory
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
        "X-AD-User": "<your-ad-username>"
      }
    }
  }
}
```

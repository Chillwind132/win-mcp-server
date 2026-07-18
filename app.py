#!/usr/bin/env python3
"""Win-MCP Server — read-only Windows remote filesystem via WinRM."""

import logging
import logging.handlers
import os
import sys

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.http import create_streamable_http_app
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from agent.session_manager import SessionRegistry, UserIdentity, current_user
from agent.prompts import register_prompts
from agent.tools import register_tools

LOG_DIR = os.environ.get("LOG_DIR", "/app/logs")
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 10 * 1024 * 1024))
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))
AD_PASSWORD_IDLE_TTL_SECONDS = int(
    os.environ.get("AD_PASSWORD_IDLE_TTL_SECONDS", "3600")
)


class AuthMiddleware(BaseHTTPMiddleware):
    """Extract per-user AD credentials from headers.

    X-AD-User is required.
    X-AD-Password is optional: when supplied it authenticates the caller with
    no prompts; when omitted the password is collected through MCP elicitation.
    The password is kept only in the in-memory SessionRegistry cache and is
    never logged.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        username = request.headers.get("x-ad-user", "").strip()

        if not username:
            return JSONResponse(
                {"error": "X-AD-User header required"},
                status_code=401,
            )

        password = request.headers.get("x-ad-password", "")

        token = current_user.set(UserIdentity(username=username, password=password))
        try:
            return await call_next(request)
        finally:
            current_user.reset(token)


def _setup_logging() -> None:
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    os.makedirs(LOG_DIR, exist_ok=True)

    root = logging.getLogger("win-mcp")
    root.setLevel(log_level)
    root.propagate = False

    stderr_fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(stderr_fmt)
    root.addHandler(stderr_handler)

    file_fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    )
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "win-mcp.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    file_handler.setFormatter(file_fmt)
    root.addHandler(file_handler)

    audit = logging.getLogger("win-mcp.audit")
    audit.setLevel(logging.INFO)
    audit.propagate = False
    audit_fmt = logging.Formatter("%(message)s")
    audit_handler = logging.handlers.RotatingFileHandler(
        os.path.join(LOG_DIR, "win-mcp-audit.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
    )
    audit_handler.setFormatter(audit_fmt)
    audit.addHandler(audit_handler)


def main() -> None:
    _setup_logging()
    logger = logging.getLogger("win-mcp")

    port = int(os.environ.get("MCPO_PORT", "8005"))

    logger.info("PORT=%d", port)

    registry = SessionRegistry(password_idle_ttl_seconds=AD_PASSWORD_IDLE_TTL_SECONDS)
    mcp = FastMCP(name="win-mcp-server")
    register_tools(mcp, registry)
    register_prompts(mcp)

    app = create_streamable_http_app(
        server=mcp,
        streamable_http_path="/mcp",
        middleware=[Middleware(AuthMiddleware)],
    )

    logger.info("win-mcp-server starting (streamable-http on port %d)", port)
    uvicorn.run(app, host=os.environ.get("MCP_BIND_HOST", "0.0.0.0"), port=port)


if __name__ == "__main__":
    main()

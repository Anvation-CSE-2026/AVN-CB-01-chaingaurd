"""Access control for a publicly reachable ChainGuard API.

Two rules, both opt-in or harmless locally:

* When ``CHAIN_GUARD_API_TOKEN`` (or ``CHAIN_GUARD_API_TOKEN_FILE``) is set,
  every route that scans, reads artifacts or talks to the remote node requires
  ``Authorization: Bearer <token>``. The comparison is constant-time. Without a
  token the service behaves exactly as before.
* Every request body is capped (``CHAIN_GUARD_MAX_REQUEST_BYTES``). A declared
  Content-Length above the cap is refused before any route runs.

Public, unauthenticated routes stay available: ``/health`` (liveness and engine
status, redacted when a token is set), ``/`` and the static dashboard under
``/ui``. The dashboard holds no credential; the operator's token is typed into
the browser at runtime and kept in memory only.
"""
from __future__ import annotations

import hmac
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import Settings

BEARER_PREFIX = "Bearer "


def is_protected_path(path: str) -> bool:
    """Routes that scan, read artifacts or contact the node."""
    return (path == "/scan" or path.startswith("/scan/")
            or path == "/remote" or path.startswith("/scans/"))


def bearer_matches(header_value: str | None, token: str) -> bool:
    """Constant-time check of an ``Authorization: Bearer`` header."""
    if not header_value or not header_value.startswith(BEARER_PREFIX):
        return False
    presented = header_value[len(BEARER_PREFIX):].strip()
    return hmac.compare_digest(presented.encode("utf-8"), token.encode("utf-8"))


def is_authorized(headers: Any, settings: Settings) -> bool:
    """True when no token is configured, or the request presents the token."""
    if not settings.api_token:
        return True
    return bearer_matches(headers.get("authorization"), settings.api_token)


def install_access_control(app: FastAPI, settings: Settings) -> None:
    """Attach the token gate and the body-size cap to ``app``."""

    @app.middleware("http")
    async def access_control(request: Request, call_next: Any) -> Any:
        declared = request.headers.get("content-length")
        if declared is not None:
            try:
                size = int(declared)
            except ValueError:
                size = -1
            if size < 0 or size > settings.max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"detail": {
                        "code": "REQUEST_TOO_LARGE",
                        "message": f"request body must be at most {settings.max_request_bytes} bytes",
                    }},
                )
        if is_protected_path(request.url.path) and not is_authorized(request.headers, settings):
            return JSONResponse(
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
                content={"detail": {"code": "UNAUTHORIZED",
                                    "message": "a valid access token is required"}},
            )
        return await call_next(request)

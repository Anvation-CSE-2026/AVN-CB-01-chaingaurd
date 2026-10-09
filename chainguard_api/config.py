"""Configuration for the ChainGuard horizontal scanning service.

No developer-specific absolute path is hard-coded anywhere in this service:
every location is either supplied through the environment or derived relative
to this file (which is portable across machines).

Environment variables
---------------------
CHAIN_GUARD_ENGINE_ROOT     directory that contains chainguard_mvp/ (default:
                            <workspace>/software supply chain mvp)
CHAIN_GUARD_ALLOWED_ROOT    canonical root repositories must live under
                            (default: <workspace>)
CHAIN_GUARD_SCAN_WORKSPACE  where isolated scan outputs are written
                            (default: <chainguard_api>/scan_workspace)
MAX_CONCURRENT_SCANS        bounded worker pool size (default: 2)
SCAN_TIMEOUT_SECONDS        per-repository subprocess timeout (default: 300)
CHAIN_GUARD_PYTHON          interpreter used to run the engine (default: current)
CHAIN_GUARD_NO_LLM          pass --no-llm to the scanner (default: true)
CHAIN_GUARD_FRONTEND_DIR    static dashboard directory served at /ui
                            (default: <workspace>/frontend; set to "none" to
                            serve the API without the dashboard)

Remote execution (optional; ``local`` is the default everywhere, so a
machine with none of these set behaves exactly as it did before)
--------------------------------------------------------------------------------
CHAIN_GUARD_EXECUTION_MODE      default execution mode for new scans:
                                ``local`` (this machine) or ``remote`` (the
                                remote node). Default: local.
CHAIN_GUARD_REMOTE_ENABLED      the gate. Remote execution is DISABLED unless
                                this is explicitly true. While it is off, no
                                entry point of this service can open a network
                                connection to a node: a remote scan fails with
                                REMOTE_EXECUTION_DISABLED and the preflight
                                reports that fact without probing anything.
                                Default: false.
CHAIN_GUARD_REMOTE_URL          base URL of the remote node, e.g.
                                http://127.0.0.1:8010. Required, and only read,
                                while the gate is on.
CHAIN_GUARD_REMOTE_TOKEN          bearer token sent to the node. Prefer
                                CHAIN_GUARD_REMOTE_TOKEN_FILE, which keeps the
                                secret out of the process environment.
CHAIN_GUARD_REMOTE_TOKEN_FILE     file containing the token (one trailing
                                newline is ignored). Read at startup.
CHAIN_GUARD_REMOTE_TIMEOUT_SECONDS  per-scan round-trip budget (default: 300)
CHAIN_GUARD_REMOTE_HEALTH_TIMEOUT_SECONDS  preflight probe budget (default: 10)
CHAIN_GUARD_REMOTE_ALLOWED_ROOT   optional: remote repository paths must resolve
                                under this prefix, as seen by the *node*.
CHAIN_GUARD_REMOTE_LABEL          optional display name for the node in
                                responses (default: host:port from the URL).

The token is never logged, echoed in a response, or printed by any report.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

CHAINGUARD_API_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = CHAINGUARD_API_DIR.parent
DEFAULT_ENGINE_DIRNAME = "software supply chain mvp"

EXECUTION_MODES = ("local", "remote")


def _positive(raw: str | None, default: int) -> int:
    try:
        value = int(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _flag(raw: str | None, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _positive_float(raw: str | None, default: float) -> float:
    try:
        value = float(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class RemoteNodeConfig:
    """How to reach the node that could execute scans on our behalf.

    Two separate facts, both required before anything leaves this machine:

    * ``enabled`` -- the explicit opt-in (``CHAIN_GUARD_REMOTE_ENABLED``). It is
      ``False`` by default, so a deployment that never asks for remote
      execution cannot reach a node, cannot be probed, and cannot make an
      outbound call from any entry point.
    * ``url`` -- where the node is. Required once the gate is on.

    ``configured`` is the conjunction of the two and is the only state in which
    a request is allowed to touch the network. A request for
    ``execution_mode=remote`` outside that state is refused -- never served
    locally -- because the caller asked for a specific machine.

    The token is excluded from ``repr`` so that an accidental log line (or a
    traceback that prints a Settings object) cannot leak it.
    """

    #: The gate. Remote execution is off unless this is explicitly true.
    enabled: bool = False
    url: str | None = None
    token: str | None = field(default=None, repr=False)
    timeout_seconds: float = 300.0
    health_timeout_seconds: float = 10.0
    #: Optional allowed-root prefix for repository paths *as the node sees them*.
    allowed_root: str | None = None
    label: str | None = None
    #: Set when CHAIN_GUARD_REMOTE_TOKEN_FILE was given but unusable, so the
    #: misconfiguration is reported rather than silently ignored.
    token_error: str | None = field(default=None, repr=False)

    @property
    def configured(self) -> bool:
        """Gate on *and* a URL set: the only state that may touch the network."""
        return bool(self.enabled and (self.url or "").strip())

    @property
    def base_url(self) -> str:
        """The URL without a trailing slash, so endpoint joins cannot double up."""
        return (self.url or "").strip().rstrip("/")

    @property
    def scheme(self) -> str:
        from urllib.parse import urlsplit

        return urlsplit(self.base_url).scheme.lower()

    @property
    def host(self) -> str:
        from urllib.parse import urlsplit

        return (urlsplit(self.base_url).hostname or "").lower()

    def redacted(self) -> dict[str, object]:
        """What is safe to disclose about the node: never the token."""
        from urllib.parse import urlsplit

        parts = urlsplit(self.base_url)
        node = None
        if parts.hostname:
            node = f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "url": self.base_url or None,
            "node": (self.label or "").strip() or node,
            "auth": "token" if self.token else "none",
            "allowed_root": self.allowed_root or None,
            "token_error": self.token_error,
        }


def read_token_file(path: str) -> tuple[str | None, str | None]:
    """Return (token, error). One trailing newline is stripped.

    Public because both the service and the ``remote_check`` CLI load the token the
    same way; there is exactly one place that knows how a token file is read.
    """
    try:
        text = Path(path).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"could not read the remote node token file ({exc.__class__.__name__})"
    token = text.rstrip("\r\n") if text.endswith(("\n", "\r")) else text
    if not token.strip():
        return None, "the remote node token file is empty"
    return token, None


def remote_config_from_env(env: "os._Environ[str] | dict[str, str]") -> RemoteNodeConfig:
    """Build the remote node configuration from the environment (never from argv).

    The gate defaults to closed: only an explicit truthful
    ``CHAIN_GUARD_REMOTE_ENABLED`` opens it.
    """
    token = env.get("CHAIN_GUARD_REMOTE_TOKEN") or None
    token_error = None
    token_file = (env.get("CHAIN_GUARD_REMOTE_TOKEN_FILE") or "").strip()
    if token is None and token_file:
        token, token_error = read_token_file(token_file)
    # An empty value must NOT open the gate: `_flag` treats "unset" and "empty"
    # differently, and a bare CHAIN_GUARD_REMOTE_ENABLED= would otherwise mean
    # "enabled". Only a present, truthful value opens it.
    raw_enabled = (env.get("CHAIN_GUARD_REMOTE_ENABLED") or "").strip() or None
    return RemoteNodeConfig(
        enabled=_flag(raw_enabled, False),
        url=(env.get("CHAIN_GUARD_REMOTE_URL") or "").strip() or None,
        token=token,
        timeout_seconds=_positive_float(env.get("CHAIN_GUARD_REMOTE_TIMEOUT_SECONDS"), 300.0),
        health_timeout_seconds=_positive_float(
            env.get("CHAIN_GUARD_REMOTE_HEALTH_TIMEOUT_SECONDS"), 10.0),
        allowed_root=(env.get("CHAIN_GUARD_REMOTE_ALLOWED_ROOT") or "").strip() or None,
        label=(env.get("CHAIN_GUARD_REMOTE_LABEL") or "").strip() or None,
        token_error=token_error,
    )


@dataclass(frozen=True)
class Settings:
    engine_root: Path
    allowed_root: Path
    workspace_dir: Path
    max_concurrent_scans: int
    scan_timeout_seconds: int
    python_executable: str
    default_no_llm: bool = True
    max_stdout_chars: int = 8000
    #: Static dashboard directory mounted at /ui. ``None`` serves the API only
    #: (used by unit tests that inject their own Settings).
    frontend_dir: Path | None = None
    #: Default execution mode for a scan that does not choose one. Requests may
    #: override it; ``local`` (this machine) is the default so nothing changes
    #: for a deployment that never configures a remote node.
    execution_mode: str = "local"
    remote: RemoteNodeConfig = field(default_factory=RemoteNodeConfig)
    #: Shared access token for every scan/artifact/remote route. ``None`` keeps
    #: the original open behaviour for local use. Set it before the service is
    #: reachable by anyone other than its operator. Never logged or echoed.
    api_token: str | None = field(default=None, repr=False)
    #: Largest request body accepted, in bytes (fleet requests are small JSON).
    max_request_bytes: int = 65536

    @classmethod
    def from_env(cls, env: "os._Environ[str] | dict[str, str] | None" = None) -> "Settings":
        env = os.environ if env is None else env
        engine_root = env.get("CHAIN_GUARD_ENGINE_ROOT") or str(
            WORKSPACE_ROOT / DEFAULT_ENGINE_DIRNAME)
        allowed_root = env.get("CHAIN_GUARD_ALLOWED_ROOT") or str(WORKSPACE_ROOT)
        workspace = env.get("CHAIN_GUARD_SCAN_WORKSPACE") or str(
            CHAINGUARD_API_DIR / "scan_workspace")
        raw_frontend = env.get("CHAIN_GUARD_FRONTEND_DIR")
        frontend = (None if raw_frontend and raw_frontend.strip().lower() in {"none", "off", ""}
                    else Path(raw_frontend).expanduser() if raw_frontend
                    else WORKSPACE_ROOT / "frontend")
        mode = (env.get("CHAIN_GUARD_EXECUTION_MODE") or "local").strip().lower()
        api_token = (env.get("CHAIN_GUARD_API_TOKEN") or "").strip() or None
        token_file = (env.get("CHAIN_GUARD_API_TOKEN_FILE") or "").strip()
        if api_token is None and token_file:
            # Same file rules as the node token; a broken file must fail the
            # service closed (see create_app), never silently open it.
            api_token, token_error = read_token_file(token_file)
            if token_error:
                raise RuntimeError(f"CHAIN_GUARD_API_TOKEN_FILE: {token_error}")
        return cls(
            api_token=api_token,
            max_request_bytes=_positive(env.get("CHAIN_GUARD_MAX_REQUEST_BYTES"), 65536),
            engine_root=Path(engine_root).expanduser(),
            allowed_root=Path(allowed_root).expanduser(),
            workspace_dir=Path(workspace).expanduser(),
            frontend_dir=frontend,
            max_concurrent_scans=_positive(env.get("MAX_CONCURRENT_SCANS"), 2),
            scan_timeout_seconds=_positive(env.get("SCAN_TIMEOUT_SECONDS"), 300),
            python_executable=env.get("CHAIN_GUARD_PYTHON") or sys.executable,
            default_no_llm=_flag(env.get("CHAIN_GUARD_NO_LLM"), True),
            execution_mode=mode if mode in EXECUTION_MODES else "local",
            remote=remote_config_from_env(env),
        )


_settings: Settings | None = None


def get_settings() -> Settings:
    """Process-wide settings singleton (tests build their own Settings)."""
    global _settings
    if _settings is None:
        _settings = Settings.from_env()
    return _settings

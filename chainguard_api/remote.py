"""Remote execution: the node client, the wire contract, and its verifier.

ChainGuard can run its engine on a second machine (the *node*) instead of
locally. The node runs the same service with the same contract, so the bridge
between the two is an *interface* -- never a code or filesystem merge. One
machine keeps the engine, API and dashboard; the other runs the engine; scans
travel over HTTP and come back as the canonical artifacts' result shape.

Nothing leaves this machine unless it was explicitly enabled: remote execution
is gated by ``CHAIN_GUARD_REMOTE_ENABLED`` and is **off by default**, and a
disabled deployment refuses remote work with ``REMOTE_EXECUTION_DISABLED``
rather than probing or connecting.

Three further rules this module exists to enforce:

1. **Never lie about where a scan ran.** A scan asked for as ``remote`` is
   refused (``503``) when no node is configured. It is never quietly executed
   locally, because the caller asked for a specific machine and a different
   answer would be false. Every result therefore carries an
   :class:`~chainguard_api.schemas.ExecutionInfo` provenance block, and a remote
   result reports *no* local artifact paths -- they do not exist here.
2. **Never trust the node's bytes.** A reply is parsed and validated against the
   canonical pydantic result model before any of it reaches a caller. A node
   that speaks a different contract (unknown top-level key, missing field,
   non-JSON body) is reported as ``REMOTE_INVALID_RESPONSE``, never silently
   normalised.
3. **Never leak the token.** It is read from the environment or a file -- never
   from argv, where it would land in the shell history and the process table --
   is excluded from ``repr``, and appears in no report, log line or error
   message. :func:`verify_remote_node` re-checks that invariant before returning.

Filesystem containment stays with the node (``chainguard_api.paths``): the
remote path names a location on *its* disk, so this module only checks the
declared remote root, and refuses relative, NUL-bearing or traversal paths.
"""
from __future__ import annotations

import json
import posixpath
import re
import time
from dataclasses import dataclass, replace
from typing import Any, Mapping
from urllib.parse import urlsplit

from pydantic import ValidationError

from .config import RemoteNodeConfig
from .paths import PathValidationError
from .schemas import RepositoryResult
from .service import failed_result

try:  # pragma: no cover - a complete install always has httpx
    import httpx
except ModuleNotFoundError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

#: Type of the injectable transport (``httpx.BaseTransport`` when available).
Transport = Any

#: Endpoints a node must expose for the bridge to be useful.
CANONICAL_ENDPOINTS: tuple[str, ...] = ("/health", "/scan", "/scan/fleet")

#: Repository id used by the opt-in preflight scan.
PROBE_REPOSITORY_ID = "remote-preflight"

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

REDACTED = "<redacted>"

#: The gate is closed: remote execution is a prepared, unopened capability.
REMOTE_EXECUTION_DISABLED = "REMOTE_EXECUTION_DISABLED"
REMOTE_EXECUTION_NOT_CONFIGURED = "REMOTE_EXECUTION_NOT_CONFIGURED"
REMOTE_CLIENT_UNAVAILABLE = "REMOTE_CLIENT_UNAVAILABLE"
REMOTE_UNREACHABLE = "REMOTE_UNREACHABLE"
REMOTE_TIMEOUT = "REMOTE_TIMEOUT"
REMOTE_AUTH_REJECTED = "REMOTE_AUTH_REJECTED"
REMOTE_REQUEST_REJECTED = "REMOTE_REQUEST_REJECTED"
REMOTE_ENGINE_UNAVAILABLE = "REMOTE_ENGINE_UNAVAILABLE"
REMOTE_INVALID_RESPONSE = "REMOTE_INVALID_RESPONSE"
REMOTE_HTTP_ERROR = "REMOTE_HTTP_ERROR"
REMOTE_PATH_NOT_ALLOWED = "REMOTE_PATH_NOT_ALLOWED"

#: code -> (http status, state, status). One table for both directions, so a
#: given failure can never be reported with two different HTTP answers.
FAILURE_MAP: dict[str, tuple[int, str, str]] = {
    REMOTE_EXECUTION_DISABLED: (503, "ENGINE_ERROR", "failed"),
    REMOTE_EXECUTION_NOT_CONFIGURED: (503, "ENGINE_ERROR", "failed"),
    REMOTE_CLIENT_UNAVAILABLE: (503, "ENGINE_ERROR", "failed"),
    REMOTE_ENGINE_UNAVAILABLE: (503, "ENGINE_ERROR", "failed"),
    REMOTE_UNREACHABLE: (502, "ENGINE_ERROR", "failed"),
    REMOTE_AUTH_REJECTED: (502, "ENGINE_ERROR", "failed"),
    REMOTE_INVALID_RESPONSE: (502, "ENGINE_ERROR", "failed"),
    REMOTE_HTTP_ERROR: (502, "ENGINE_ERROR", "failed"),
    REMOTE_REQUEST_REJECTED: (400, "INVALID_INPUT", "failed"),
    REMOTE_PATH_NOT_ALLOWED: (400, "INVALID_INPUT", "failed"),
    REMOTE_TIMEOUT: (504, "TIMEOUT", "timeout"),
}


def failure_triple(code: str) -> tuple[int, str, str]:
    """(http status, state, status) for a remote failure code."""
    return FAILURE_MAP.get(code, (502, "ENGINE_ERROR", "failed"))


class RemoteError(Exception):
    """A remote execution failure that already knows its HTTP answer."""

    def __init__(self, code: str, message: str, *, http_status: int | None = None,
                 state: str | None = None, status: str | None = None) -> None:
        super().__init__(message)
        mapped_status, mapped_state, mapped_result = failure_triple(code)
        self.code = code
        self.message = message
        self.http_status = http_status if http_status is not None else mapped_status
        self.state = state if state is not None else mapped_state
        self.status = status if status is not None else mapped_result


@dataclass(frozen=True)
class RemoteOutcome:
    """Result of one remote scan: the canonical body plus the HTTP answer."""

    result: dict[str, Any]
    http_status: int = 200


# --------------------------------------------------------------------- paths

_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")


def canonical_remote_path(raw: str | None) -> str:
    """Lexically normalise a path that lives on the *node*.

    ``..`` is collapsed textually so a traversal attempt cannot slip past the
    declared-root prefix check. This is defence in depth only -- the node
    applies its own containment rules to the real filesystem, and this module
    never touches the node's disk.
    """
    text = str(raw if raw is not None else "").replace("\\", "/").strip()
    if not text:
        raise PathValidationError("remote repository path is required",
                                  code=REMOTE_PATH_NOT_ALLOWED)
    if "\x00" in text:
        raise PathValidationError("remote repository path contains a NUL byte",
                                  code=REMOTE_PATH_NOT_ALLOWED)
    return posixpath.normpath(text)


def _remote_is_within(path: str, root: str) -> bool:
    left, right = path, root.rstrip("/")
    if _DRIVE.match(left) or _DRIVE.match(right):
        left, right = left.lower(), right.lower()
    return left == right or left.startswith(right + "/")


def validate_remote_repository_path(raw: str | None,
                                    allowed_root: str | None = None) -> str:
    """Return the normalised remote path, or raise PathValidationError.

    The path must be absolute *as the node sees it*; a relative path would let
    the node resolve it against its own working directory, which we cannot
    predict and must not guess at.
    """
    text = canonical_remote_path(raw)
    if not text.startswith("/") and not _WINDOWS_ABSOLUTE.match(text):
        raise PathValidationError(
            "remote repository path must be absolute as seen by the node",
            code=REMOTE_PATH_NOT_ALLOWED)
    if allowed_root:
        root = canonical_remote_path(allowed_root)
        if not _remote_is_within(text, root):
            raise PathValidationError(
                f"remote repository path is outside the declared remote root ({root})",
                code=REMOTE_PATH_NOT_ALLOWED)
    return text


# ----------------------------------------------------------------------- url

def remote_url_problem(url: str) -> str | None:
    """Why this is not a usable node base URL, or ``None`` if it is."""
    if not url:
        return "no remote node is configured (CHAIN_GUARD_REMOTE_URL is unset)"
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        return (f"the remote url must start with http:// or https:// "
                f"(got scheme {parts.scheme or '<none>'!r})")
    if not parts.hostname:
        return "the remote url has no host"
    if parts.username or parts.password:
        return ("the remote url must not embed credentials in the URL; use "
                "CHAIN_GUARD_REMOTE_TOKEN or CHAIN_GUARD_REMOTE_TOKEN_FILE instead")
    if parts.query or parts.fragment:
        return "the remote url must not contain a query string or fragment"
    return None


def is_loopback(config: RemoteNodeConfig) -> bool:
    return (urlsplit(config.base_url).hostname or "").lower() in LOOPBACK_HOSTS


# -------------------------------------------------------------------- client

def _require_httpx() -> None:
    if httpx is None:  # pragma: no cover - only on an incomplete install
        raise RemoteError(
            REMOTE_CLIENT_UNAVAILABLE,
            "the httpx package is not installed in this interpreter, so remote "
            "execution is unavailable; install it with 'pip install -r "
            "chainguard_api/requirements.txt' (local scans are unaffected)",
            http_status=503)


class RemoteNodeClient:
    """Minimal, fail-closed HTTP client for one node."""

    def __init__(self, config: RemoteNodeConfig, *, transport: Transport | None = None) -> None:
        self.config = config
        self._transport = transport

    # -- plumbing ---------------------------------------------------------

    def require_ready(self) -> None:
        """Raise unless this deployment is actually allowed to touch the network.

        The gate is checked first, so a deployment that never enabled remote
        execution cannot reach a node, cannot be probed, and does not even need
        the HTTP client to be installed.
        """
        if not self.config.enabled:
            raise RemoteError(
                REMOTE_EXECUTION_DISABLED,
                "remote execution is disabled on this deployment; set "
                "CHAIN_GUARD_REMOTE_ENABLED=true to enable it "
                "(the scan will not be run locally instead)",
                http_status=503)
        _require_httpx()
        if not (self.config.url or "").strip():
            raise RemoteError(
                REMOTE_EXECUTION_NOT_CONFIGURED,
                "remote execution is enabled but no remote node is configured; set "
                "CHAIN_GUARD_REMOTE_URL (the scan will not be run locally instead)",
                http_status=503)
        problem = remote_url_problem(self.config.base_url)
        if problem:
            raise RemoteError(REMOTE_EXECUTION_NOT_CONFIGURED, problem, http_status=503)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        return headers

    def request(self, method: str, path: str, *, timeout: float,
                json_body: Any = None) -> Any:
        """One HTTP call; every transport failure becomes a RemoteError.

        Redirects are deliberately *not* followed: a 3xx means the base URL is
        wrong, and following it would hand our token to whatever host it names.
        """
        self.require_ready()
        try:
            with httpx.Client(base_url=self.config.base_url, timeout=timeout,
                              follow_redirects=False, transport=self._transport,
                              headers=self._headers()) as client:
                return client.request(method, path, json=json_body)
        except httpx.TimeoutException:
            raise RemoteError(
                REMOTE_TIMEOUT,
                f"the node did not answer {method} {path} within {timeout:g}s",
                http_status=504, state="TIMEOUT", status="timeout") from None
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise RemoteError(
                REMOTE_UNREACHABLE,
                f"could not reach the node at {self.config.base_url or '<unset>'} "
                f"({type(exc).__name__})",
                http_status=502) from None

    def json_of(self, response: Any, path: str) -> dict[str, Any]:
        """A JSON object body, or REMOTE_INVALID_RESPONSE -- never anything else."""
        try:
            payload = response.json()
        except ValueError:
            raise RemoteError(REMOTE_INVALID_RESPONSE,
                            f"{path} did not return JSON",
                            http_status=502) from None
        if not isinstance(payload, dict):
            raise RemoteError(REMOTE_INVALID_RESPONSE,
                            f"{path} returned JSON that is not an object",
                            http_status=502)
        return payload

    def health(self, *, timeout: float | None = None) -> dict[str, Any]:
        """GET /health with the normal status interpretation."""
        budget = timeout if timeout is not None else self.config.health_timeout_seconds
        response = self.request("GET", "/health", timeout=budget)
        if response.status_code in (401, 403):
            raise RemoteError(REMOTE_AUTH_REJECTED,
                            f"the node rejected our credentials for GET /health "
                            f"({response.status_code})", http_status=502)
        if response.status_code != 200:
            raise RemoteError(REMOTE_HTTP_ERROR,
                            f"GET /health answered {response.status_code}",
                            http_status=502)
        return self.json_of(response, "/health")


# --------------------------------------------------------------------- scans

def _node_error_message(payload: Mapping[str, Any] | None, fallback: str) -> str:
    error = (payload or {}).get("error")
    if isinstance(error, dict):
        code = error.get("code") or "?"
        message = str(error.get("message") or "").strip()
        if message:
            return f"the node refused the scan: {message} ({code})"
    return fallback


def fetch_scan(client: RemoteNodeClient, *, repository_id: str, repository_path: str,
               options: Mapping[str, Any] | None = None,
               timeout: float | None = None) -> tuple[dict[str, Any], int]:
    """POST /scan to the node and validate the reply.

    Returns the node's own payload (byte-for-byte as it sent it, so no evidence
    is dropped) and the locally measured round-trip time. Raises RemoteError for
    anything that is not a canonical result.
    """
    budget = timeout if timeout is not None else client.config.timeout_seconds
    options = options or {}
    body = {
        "repository": {"id": repository_id, "path": repository_path},
        "options": {key: options[key] for key in
                    ("no_llm", "fail_on_actionable", "dashboard", "diff_ref")
                    if key in options},
    }
    started = time.perf_counter()
    response = client.request("POST", "/scan", timeout=budget, json_body=body)
    latency_ms = int((time.perf_counter() - started) * 1000)
    status = response.status_code
    node = client.config.base_url or "<unset>"

    # Read the body regardless of status: the node's own error message is the
    # most useful thing to relay, and a non-JSON body must not crash the bridge.
    try:
        payload: dict[str, Any] | None = client.json_of(response, "/scan")
    except RemoteError:
        payload = None

    if status in (301, 302, 303, 307, 308):
        raise RemoteError(REMOTE_HTTP_ERROR,
                        f"the node redirected POST /scan ({status}); refusing to "
                        f"follow a redirect with credentials. Check that "
                        f"CHAIN_GUARD_REMOTE_URL points at the node's root "
                        f"({node})", http_status=502)
    if status in (401, 403):
        raise RemoteError(REMOTE_AUTH_REJECTED,
                        f"the node rejected our credentials for POST /scan ({status}); "
                        "check CHAIN_GUARD_REMOTE_TOKEN", http_status=502)
    if status in (404, 405):
        raise RemoteError(REMOTE_HTTP_ERROR,
                        f"the node at {node} does not expose POST /scan ({status}); "
                        "it may not be a ChainGuard API, or the base URL may be wrong",
                        http_status=502)
    if status == 504:
        raise RemoteError(REMOTE_TIMEOUT, _node_error_message(
            payload, "the node reported that its scan timed out"),
            http_status=504, state="TIMEOUT", status="timeout")
    if status == 503:
        raise RemoteError(REMOTE_ENGINE_UNAVAILABLE, _node_error_message(
            payload, "the node cannot run the engine right now"), http_status=503)
    if status in (400, 422):
        raise RemoteError(REMOTE_REQUEST_REJECTED, _node_error_message(
            payload, f"the node rejected the request ({status})"), http_status=400)
    if status != 200:
        raise RemoteError(REMOTE_HTTP_ERROR,
                        f"POST /scan answered {status}", http_status=502)

    if payload is None:
        raise RemoteError(REMOTE_INVALID_RESPONSE,
                        "POST /scan returned 200 with a body that is not JSON",
                        http_status=502)
    try:
        RepositoryResult.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(part) for part in first.get("loc", ())) or "<body>"
        raise RemoteError(
            REMOTE_INVALID_RESPONSE,
            "the node's reply does not match the canonical result contract "
            f"({exc.error_count()} validation error(s); first at {where}: "
            f"{first.get('msg', 'invalid')}). The bridge refuses to forward it.",
            http_status=502)
    return payload, latency_ms


def _artifact_note(node_artifacts: Mapping[str, Any] | None, node: str) -> str:
    names = [name for name, key in (("report.json", "report"), ("sbom.cdx.json", "sbom"),
                                    ("openvex.json", "vex"), ("trace.json", "trace"))
             if isinstance(node_artifacts, Mapping) and node_artifacts.get(key)]
    listed = ", ".join(names) if names else "no artifact was reported"
    return (f"the scan ran on {node}; its artifacts ({listed}) were written on that "
            f"machine and this deployment stores none of them")


def _provenance(config: RemoteNodeConfig, *, remote_scan_id: str | None = None,
                latency_ms: int | None = None,
                node_artifacts: Mapping[str, Any] | None = None,
                note: str | None = None, artifacts_remote: bool = True) -> dict[str, Any]:
    node = config.label.strip() if (config.label or "").strip() else None
    if node is None:
        parts = urlsplit(config.base_url)
        node = (f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname) or None
    return {
        "mode": "remote",
        "node": node,
        "remote_scan_id": remote_scan_id,
        "latency_ms": latency_ms,
        "artifacts_remote": artifacts_remote,
        "note": note if note is not None else (
            _artifact_note(node_artifacts, node or "the node") if artifacts_remote else None),
    }


def _remote_failure(error: RemoteError, repository_id: str, repository_path: str,
                    config: RemoteNodeConfig) -> dict[str, Any]:
    """A remote failure in exactly the canonical shape, still marked remote."""
    result = failed_result(
        repository_id, str(repository_path), error.code, error.message, error.state,
        execution=_provenance(config, artifacts_remote=False))
    # failed_result always says "failed"; a timeout keeps the API's documented
    # timeout semantics (status "timeout", state "TIMEOUT", HTTP 504).
    if error.status != "failed":
        result["status"] = error.status
    return result


def scan_remote(repository_id: str, repository_path: str,
                options: Mapping[str, Any] | None, config: RemoteNodeConfig,
                *, transport: Transport | None = None) -> RemoteOutcome:
    """Run one scan on the node and return the canonical result shape."""
    try:
        path = validate_remote_repository_path(repository_path, config.allowed_root)
        client = RemoteNodeClient(config, transport=transport)
        payload, latency_ms = fetch_scan(client, repository_id=repository_id,
                                         repository_path=path, options=options)
    except PathValidationError as exc:
        error = RemoteError(exc.code, str(exc))
        return RemoteOutcome(_remote_failure(error, repository_id, repository_path,
                                             config), error.http_status)
    except RemoteError as exc:
        return RemoteOutcome(_remote_failure(exc, repository_id, repository_path,
                                             config), exc.http_status)

    remote_scan_id = payload.get("scan_id")
    result = dict(payload)
    result["scan_id"] = remote_scan_id
    # The node's own provenance describes the node's local run; from here the
    # honest statement is that the work happened elsewhere.
    result["execution"] = _provenance(
        config,
        remote_scan_id=remote_scan_id if isinstance(remote_scan_id, str) else None,
        latency_ms=latency_ms,
        node_artifacts=payload.get("artifacts"),
    )
    # Its artifact paths name files on the node's disk. Forwarding them would
    # invite a caller to open a path that does not exist on this machine.
    result["artifacts"] = None
    return RemoteOutcome(result, 200)


# ------------------------------------------------------------------ verifier

def _verdict(checks: list[dict[str, Any]]) -> str:
    statuses = {check["status"] for check in checks}
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def _finalize(report: dict[str, Any], checks: list[dict[str, Any]],
              config: RemoteNodeConfig) -> dict[str, Any]:
    """Attach the checks, re-check secret hygiene, then compute the verdict.

    The sweep runs after every check has been added and before the verdict, so a
    token that somehow reached a detail string is removed from the returned
    report rather than merely flagged.
    """
    report["checks"] = checks
    token = config.token or ""
    if token and token in json.dumps(report, default=str):
        report = _redact(report, token)
        report["checks"].append(
            {"name": "secret_hygiene", "status": "warn",
             "detail": "a token value was found in this report and redacted before "
                       "returning it"})
    else:
        report["checks"].append(
            {"name": "secret_hygiene", "status": "pass",
             "detail": "the token (if any) does not appear anywhere in this report"})
    report["verdict"] = _verdict(report["checks"])
    report["ok"] = report["verdict"] == "pass"
    return report


def _redact(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, REDACTED)
    if isinstance(value, dict):
        return {key: _redact(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, secret) for item in value]
    return value


def verify_remote_node(config: RemoteNodeConfig, *, transport: Transport | None = None,
                probe_repository: str | None = None) -> dict[str, Any]:
    """Read-only preflight of a node against the canonical contract.

    Nothing here mutates the node: it reads ``/health`` and ``/openapi.json``,
    checks which HTTP methods ``/scan`` answers without ever submitting a valid
    body, and only runs a real scan when ``probe_repository`` is given.
    """
    checks: list[dict[str, Any]] = []

    def record(name: str, status: str, detail: str = "",
               latency_ms: int | None = None) -> str:
        entry: dict[str, Any] = {"name": name, "status": status, "detail": detail}
        if latency_ms is not None:
            entry["latency_ms"] = latency_ms
        checks.append(entry)
        return status

    report: dict[str, Any] = {
        "remote": config.redacted(),
        "contract": {"openapi_read": False, "endpoints": {}},
        "engine": None,
        "scan_probe": None,
    }

    # -- the gate ---------------------------------------------------------
    # Checked before anything else, and it ends the preflight here: while remote
    # execution is disabled this function performs no network call at all, so
    # "the deployment is closed" is reported without probing a node.
    if not config.enabled:
        record("enabled", "fail",
               "remote execution is disabled on this deployment; set "
               "CHAIN_GUARD_REMOTE_ENABLED=true to enable it (nothing was probed)")
        return _finalize(report, checks, config)
    record("enabled", "pass", "remote execution is explicitly enabled")

    # -- configuration ----------------------------------------------------
    problem = remote_url_problem(config.base_url)
    if not config.configured:
        record("configured", "fail",
               "remote execution is enabled but no remote node is configured; set "
               "CHAIN_GUARD_REMOTE_URL")
    elif problem:
        record("configured", "fail", problem)
    elif config.scheme == "http" and not is_loopback(config):
        record("configured", "warn",
               f"the node is addressed over plain http at {config.base_url}; the "
               "bearer token and every scan result travel unencrypted. Use https "
               "or a private link")
    else:
        record("configured", "pass", f"{config.base_url} ({config.scheme})")

    # Without a usable URL there is nothing to probe, so stop here rather than
    # reporting network failures that only restate the configuration problem.
    if not config.configured or problem:
        return _finalize(report, checks, config)

    if config.token_error:
        record("token", "fail", config.token_error)
    elif config.token:
        record("token", "pass", "a bearer token is configured (value never disclosed)")
    elif is_loopback(config):
        record("token", "pass", "no token configured; loopback node")
    else:
        record("token", "warn",
               "no token is configured, so this deployment will call the node "
               "unauthenticated; the node must be reachable only over a private link")

    client = RemoteNodeClient(config, transport=transport)
    health: dict[str, Any] | None = None

    # -- reachability -----------------------------------------------------
    started = time.perf_counter()
    try:
        response = client.request("GET", "/health", timeout=config.health_timeout_seconds)
    except RemoteError as exc:
        record("reachable", "fail", exc.message,
               int((time.perf_counter() - started) * 1000))
    else:
        latency = int((time.perf_counter() - started) * 1000)
        if response.status_code in (401, 403):
            record("reachable", "fail",
                   f"GET /health answered {response.status_code}: our credentials were "
                   "rejected (check CHAIN_GUARD_REMOTE_TOKEN)", latency)
        elif response.status_code != 200:
            record("reachable", "fail",
                   f"GET /health answered {response.status_code}", latency)
        else:
            record("reachable", "pass", "GET /health answered 200", latency)
            try:
                health = client.json_of(response, "/health")
            except RemoteError as exc:
                record("health_contract", "fail", exc.message)

    if health is not None:
        engine = health.get("engine")
        node_status = health.get("status")
        if node_status not in {"ok", "degraded"}:
            record("health_contract", "fail",
                   f"the node's /health status is {node_status!r}, not 'ok' or 'degraded'; "
                   "it may not be a ChainGuard API")
        elif not isinstance(engine, dict):
            record("health_contract", "fail",
                   "the node's /health has no engine block, so it cannot report whether "
                   "its engine is runnable")
        else:
            missing = [key for key in ("available", "implementation", "entrypoint")
                       if key not in engine]
            if missing:
                record("health_contract", "fail",
                       "the node's engine block is missing: " + ", ".join(missing))
            else:
                report["engine"] = engine
                record("health_contract", "pass",
                       f"the node reports engine {engine.get('implementation')} at "
                       f"{engine.get('entrypoint')}")
                if node_status == "ok" and engine.get("available"):
                    record("engine", "pass",
                           f"the node's engine is runnable ({engine.get('path') or 'path unstated'})")
                else:
                    detail = engine.get("detail") or "the node reports no usable engine"
                    record("engine", "fail",
                           f"the node cannot run scans: {detail}")

    # -- contract ---------------------------------------------------------
    paths: dict[str, Any] = {}
    try:
        response = client.request("GET", "/openapi.json",
                                  timeout=config.health_timeout_seconds)
    except RemoteError as exc:
        record("contract", "warn",
               f"could not read /openapi.json ({exc.code}), so endpoint presence "
               "could not be confirmed")
    else:
        if response.status_code != 200:
            record("contract", "warn",
                   f"/openapi.json answered {response.status_code}, so endpoint presence "
                   "could not be confirmed")
        else:
            try:
                schema = client.json_of(response, "/openapi.json")
            except RemoteError as exc:
                record("contract", "warn", f"/openapi.json was unusable ({exc.message})")
            else:
                raw_paths = schema.get("paths")
                paths = raw_paths if isinstance(raw_paths, dict) else {}
                report["contract"]["openapi_read"] = True
                report["contract"]["endpoints"] = {
                    endpoint: sorted((paths.get(endpoint) or {}).keys())
                    for endpoint in CANONICAL_ENDPOINTS if endpoint in paths}
                if "/scan" not in paths:
                    record("contract", "fail",
                           "the node's schema has no /scan path; it cannot be used as an "
                           "execution node")
                else:
                    missing = [endpoint for endpoint in CANONICAL_ENDPOINTS
                               if endpoint not in paths]
                    record("contract", "pass" if not missing else "warn",
                           "the node exposes " + ", ".join(
                               f"{endpoint} [{', '.join(report['contract']['endpoints'][endpoint]) or '?'}]"
                               for endpoint in CANONICAL_ENDPOINTS
                               if endpoint in report["contract"]["endpoints"])
                           + ("" if not missing else "; missing " + ", ".join(missing)))

    # -- how /scan answers a method it should not -------------------------
    try:
        response = client.request("GET", "/scan", timeout=config.health_timeout_seconds)
    except RemoteError as exc:
        record("scan_method_guard", "warn", f"could not probe GET /scan ({exc.code})")
    else:
        if response.status_code == 405:
            record("scan_method_guard", "pass",
                   "GET /scan is refused with 405, so only one POST handler owns /scan")
        elif response.status_code == 404:
            record("scan_method_guard", "fail",
                   "there is no route at /scan on the node (404)")
        elif response.status_code == 200:
            record("scan_method_guard", "fail",
                   "GET /scan answered 200: a handler accepts GET on the scan path, "
                   "which is the signature of a second, duplicated /scan route. The "
                   "duplicate must be removed on the node before bridging")
        else:
            record("scan_method_guard", "warn",
                   f"GET /scan answered {response.status_code}, which is neither the "
                   "canonical 405 nor a duplicate-route 200")

    # -- does /scan enforce the canonical request schema? -----------------
    # The bodies below are invalid by construction, so a conforming node rejects
    # them before any scan starts: an empty body has no repository, and the
    # second has an empty path (min_length=1) plus an unknown top-level field.
    probes = (
        ("scan_requires_body", {},
         "a request body without 'repository' was accepted"),
        ("scan_rejects_unknown_fields",
         {"repository": {"id": PROBE_REPOSITORY_ID, "path": ""}, "unexpected_field": True},
         "an unknown top-level field was accepted, so the node does not enforce the "
         "canonical strict schema"),
    )
    for name, body, complaint in probes:
        try:
            response = client.request("POST", "/scan", timeout=config.health_timeout_seconds,
                                      json_body=body)
        except RemoteError as exc:
            record(name, "warn", f"could not probe POST /scan ({exc.code}: {exc.message})")
            continue
        if response.status_code == 422:
            record(name, "pass", "the node rejects the invalid body with 422")
        else:
            record(name, "fail",
                   f"{complaint} (POST /scan answered {response.status_code} instead of "
                   "422); the node's /scan does not match the canonical contract")

    # -- is authentication enforced? --------------------------------------
    if config.token:
        anonymous = RemoteNodeClient(replace(config, token=None), transport=transport)
        try:
            response = anonymous.request("GET", "/health",
                                         timeout=config.health_timeout_seconds)
        except RemoteError as exc:
            record("auth_enforced", "warn",
                   f"could not probe an unauthenticated request ({exc.code})")
        else:
            if response.status_code in (401, 403):
                record("auth_enforced", "pass",
                       f"the node refuses unauthenticated requests ({response.status_code})")
            elif response.status_code == 200:
                record("auth_enforced", "warn",
                       "the node answers GET /health without credentials, so it does not "
                       "enforce authentication; it must be reachable only over a private link")
            else:
                record("auth_enforced", "warn",
                       f"an unauthenticated GET /health answered {response.status_code}")

    # -- opt-in real scan --------------------------------------------------
    if probe_repository:
        try:
            path = validate_remote_repository_path(probe_repository, config.allowed_root)
        except PathValidationError as exc:
            record("scan_probe", "fail", str(exc))
        else:
            try:
                payload, latency_ms = fetch_scan(client, repository_id=PROBE_REPOSITORY_ID,
                                                 repository_path=path,
                                                 options={"no_llm": True})
            except RemoteError as exc:
                record("scan_probe", "fail", f"{exc.code}: {exc.message}")
            else:
                summary = payload.get("summary") or {}
                report["scan_probe"] = {
                    "repository": payload.get("repository"),
                    "status": payload.get("status"),
                    "state": payload.get("state"),
                    "scan_id": payload.get("scan_id"),
                    "summary": summary,
                    "latency_ms": latency_ms,
                }
                counts = (f"{summary.get('total_vulnerabilities', 0)} advisories / "
                          f"{summary.get('dismissed_unreachable', 0)} unreachable / "
                          f"{summary.get('actionable', 0)} actionable / "
                          f"{summary.get('suspicious_packages', 0)} suspicious")
                if payload.get("status") == "completed":
                    record("scan_probe", "pass",
                           f"a real scan on the node returned the canonical shape "
                           f"({counts}) in {latency_ms} ms", latency_ms)
                else:
                    record("scan_probe", "warn",
                           f"the node answered with status {payload.get('status')!r} "
                           f"({counts})", latency_ms)
    else:
        record("scan_probe", "skipped",
               "no scan was run on the node; pass --probe-repository to run one")

    return _finalize(report, checks, config)

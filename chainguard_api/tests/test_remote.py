"""Remote execution: the node contract verifier and the fail-closed bridge.

Two layers are covered:

* ``verify_remote_node`` -- the read-only preflight, exercised against a stand-in node
  over an ``httpx.MockTransport`` so every branch (degraded engine, duplicate
  ``/scan`` handling, divergent schema, rejected token, unreachable host) is
  reachable without a second machine;
* the API itself -- ``execution_mode=remote`` must run the engine on the node
  and *only* there. Several tests use a runner that raises if it is ever called,
  which is what makes "no silent local fallback" a proven property rather than a
  claim.
"""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from chainguard_api import remote as remote_module
from chainguard_api.app import create_app
from chainguard_api.config import RemoteNodeConfig, Settings
from chainguard_api.remote import (
    REMOTE_EXECUTION_DISABLED,
    REMOTE_INVALID_RESPONSE,
    REMOTE_EXECUTION_NOT_CONFIGURED,
    REMOTE_REQUEST_REJECTED,
    REMOTE_TIMEOUT,
    REMOTE_PATH_NOT_ALLOWED,
    canonical_remote_path,
    fetch_scan,
    remote_url_problem,
    scan_remote,
    validate_remote_repository_path,
    verify_remote_node,
)
from conftest import fake_runner, report_payload

TOKEN = "test-token-value"

CANONICAL_ENGINE = {
    "available": True, "implementation": "real", "type": "real",
    "entrypoint": "chainguard_mvp.cli", "path": "/node/engine",
}


def canonical_scan_payload(repository: dict, *, scan_id: str = "a" * 32,
                           extra_body: dict | None = None) -> dict:
    """What our own API would return for a successful scan on the node."""
    report = report_payload(repository["path"])
    payload = {
        "repository": repository,
        # the node's own provenance describes ITS local run and must be replaced
        "execution": {"mode": "local", "artifacts_remote": False},
        "scan_id": scan_id,
        "status": "completed",
        "state": "COMPLETED",
        "scan": {"exit_code": 0, "duration_ms": 12,
                 "command": ["node-python", "-m", "chainguard_mvp.cli"],
                 "stdout": "scanning\n", "stderr": ""},
        "summary": report["summary"],
        "vulnerabilities": report["vulnerabilities"],
        "suspicious_packages": report["suspicious_packages"],
        "unresolved_dependencies": [],
        "artifacts": {"report": "/node/out/report.json", "sbom": "/node/out/sbom.cdx.json",
                      "vex": "/node/out/openvex.json", "trace": "/node/out/trace.json"},
        "artifact_names": {"report": "report.json", "sbom": "sbom.cdx.json",
                           "vex": "openvex.json", "trace": "trace.json"},
        "error": None,
    }
    if extra_body:
        payload.update(extra_body)
    return payload


class FakeNode:
    """A stand-in node: canonical by default, wrong in exactly one way on demand.

    ``bad_schema``, ``get_scan_answers``, ``degraded_engine``, ``reject_token``
    and ``enforce_auth`` each reproduce one real failure mode; ``scan_body``
    overrides the /scan response body outright.
    """

    def __init__(self, *, degraded_engine: bool = False, enforce_auth: bool = False,
                 reject_token: bool = False, get_scan_answers: bool = False,
                 bad_schema: bool = False, scan_body: object = None,
                 scan_status: int = 200, health_text: str | None = None,
                 openapi: bool = True) -> None:
        self.degraded_engine = degraded_engine
        self.enforce_auth = enforce_auth
        self.reject_token = reject_token
        self.get_scan_answers = get_scan_answers
        self.bad_schema = bad_schema
        self.scan_body = scan_body
        self.scan_status = scan_status
        self.health_text = health_text
        self.openapi = openapi
        self.requests: list[tuple[str, str]] = []

    # -- helpers ----------------------------------------------------------
    def _authorized(self, request: httpx.Request) -> bool:
        if self.reject_token:
            return False
        if not self.enforce_auth:
            return True
        return request.headers.get("authorization") == f"Bearer {TOKEN}"

    def _health(self) -> httpx.Response:
        if self.health_text is not None:
            return httpx.Response(200, text=self.health_text,
                                  headers={"content-type": "text/plain"})
        engine = dict(CANONICAL_ENGINE)
        status = "ok"
        if self.degraded_engine:
            status = "degraded"
            engine.update({"available": False, "implementation": "missing",
                           "detail": "engine dependency 'requests' is missing"})
        return httpx.Response(200, json={"status": status, "engine": engine})

    def _valid_scan_request(self, body: object) -> bool:
        """Mirror the canonical strict schema: extra=forbid, path min_length=1."""
        if self.bad_schema or not isinstance(body, dict):
            return True
        if set(body) - {"repository", "options"}:
            return False
        repository = body.get("repository")
        if not isinstance(repository, dict):
            return False
        if set(repository) - {"id", "path"}:
            return False
        return bool(str(repository.get("path") or ""))

    # -- transport --------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.requests.append((method, path))
        if path == "/health":
            if not self._authorized(request):
                return httpx.Response(401, json={"detail": "unauthorized"})
            return self._health()
        if path == "/scan/fleet":
            return httpx.Response(200, json={"scan_id": "f" * 32, "status": "completed",
                                             "summary": {}, "results": []})
        if path == "/scan":
            if not self.get_scan_answers and method == "GET":
                return httpx.Response(405, json={"detail": "Method Not Allowed"})
            if self.get_scan_answers and method == "GET":
                return httpx.Response(200, json={"status": "ok"})
            if not self._authorized(request):
                return httpx.Response(401, json={"detail": "unauthorized"})
            body = json.loads(request.content or b"{}")
            if not self._valid_scan_request(body):
                return httpx.Response(422, json={"detail": [
                    {"loc": ["body"], "msg": "invalid request", "type": "value_error"}]})
            if self.bad_schema:
                # A node whose /scan does not enforce the canonical schema still
                # has to answer these probes; that is the point of the check.
                return httpx.Response(200, json={"status": "completed"})
            if self.scan_body is not None:
                if isinstance(self.scan_body, str):
                    return httpx.Response(self.scan_status, text=self.scan_body,
                                          headers={"content-type": "text/plain"})
                return httpx.Response(self.scan_status, json=self.scan_body)
            return httpx.Response(200, json=canonical_scan_payload(body["repository"]))
        if path == "/openapi.json":
            if not self.openapi:
                return httpx.Response(404, json={"detail": "not found"})
            return httpx.Response(200, json={"paths": {
                "/health": {"get": {}}, "/scan": {"post": {}}, "/scan/fleet": {"post": {}}}})
        return httpx.Response(404, json={"detail": "no such route"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def node_config(**overrides) -> RemoteNodeConfig:
    """An enabled node by default; pass ``enabled=False`` to test the closed gate."""
    values = {"enabled": True, "url": "http://127.0.0.1:8010", "token": TOKEN,
              "label": "friends-laptop"}
    values.update(overrides)
    return RemoteNodeConfig(**values)


def remote_settings(settings: Settings, *, config: RemoteNodeConfig | None = None,
                  mode: str = "local", **overrides) -> Settings:
    values = {
        "engine_root": settings.engine_root,
        "allowed_root": settings.allowed_root,
        "workspace_dir": settings.workspace_dir,
        "max_concurrent_scans": settings.max_concurrent_scans,
        "scan_timeout_seconds": settings.scan_timeout_seconds,
        "python_executable": settings.python_executable,
        "execution_mode": mode,
        "remote": config if config is not None else RemoteNodeConfig(),
    }
    values.update(overrides)
    return Settings(**values)


class LocalEngineGuard:
    """A runner that must never be called: proves a remote scan stayed remote."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, command, cwd, timeout):
        self.calls += 1
        raise AssertionError("the local engine was invoked for a remote scan")


def _checks(report: dict) -> dict[str, dict]:
    return {check["name"]: check for check in report["checks"]}


# ------------------------------------------------------------ remote paths

@pytest.mark.parametrize("raw, expected", [
    ("/node/repos/app", "/node/repos/app"),
    ("/node/repos/app/", "/node/repos/app"),
    ("/node/repos/../repos/app", "/node/repos/app"),
    ("C:\\node\\repos\\app", "C:/node/repos/app"),
    ("//fileserver/share/app", "//fileserver/share/app"),
])
def test_remote_paths_are_normalised(raw: str, expected: str) -> None:
    assert canonical_remote_path(raw) == expected


def test_remote_path_is_confined_to_the_declared_root() -> None:
    assert validate_remote_repository_path(
        "/node/repos/app/deep", "/node/repos") == "/node/repos/app/deep"
    assert validate_remote_repository_path(
        "/node/repos/../repos/app", "/node/repos") == "/node/repos/app"
    # a traversal that escapes the declared root is refused
    with pytest.raises(Exception) as excinfo:
        validate_remote_repository_path("/node/repos/../../etc", "/node/repos")
    assert getattr(excinfo.value, "code", None) == REMOTE_PATH_NOT_ALLOWED


def test_remote_path_must_be_absolute_and_nul_free() -> None:
    for bad in ("repos/app", "", "   ", None, "/node/repos\x00/app"):
        with pytest.raises(Exception) as excinfo:
            validate_remote_repository_path(bad, None)
        assert getattr(excinfo.value, "code", None) == REMOTE_PATH_NOT_ALLOWED


@pytest.mark.parametrize("url, problem", [
    ("ftp://host/scan", True),
    ("http://", True),
    ("http://user:pw@host:8010", True),
    ("http://host:8010/?x=1", True),
    ("http://host:8010/#frag", True),
    ("", True),
    ("http://127.0.0.1:8010", False),
    ("https://node.internal:8010", False),
])
def test_remote_url_validation(url: str, problem: bool) -> None:
    assert (remote_url_problem(url) is not None) is problem


# ---------------------------------------------------------------- verifier

def test_preflight_passes_on_a_conforming_node() -> None:
    node = FakeNode(enforce_auth=True)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert report["verdict"] == "pass", report["checks"]
    assert report["ok"] is True
    assert report["contract"]["openapi_read"] is True
    assert report["engine"]["implementation"] == "real"
    checks = _checks(report)
    assert checks["scan_method_guard"]["status"] == "pass"
    assert checks["scan_probe"]["status"] == "skipped"
    # the preflight itself never submitted a valid scan request
    assert ("POST", "/scan") in node.requests
    assert report["scan_probe"] is None


def test_preflight_fails_when_a_handler_answers_get_scan() -> None:
    """The duplicate-/scan symptom: something other than the canonical POST owns the path."""
    node = FakeNode(enforce_auth=True, get_scan_answers=True)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert report["verdict"] == "fail"
    detail = _checks(report)["scan_method_guard"]["detail"]
    assert "duplicated /scan route" in detail


def test_preflight_fails_when_the_node_does_not_enforce_the_schema() -> None:
    node = FakeNode(enforce_auth=True, bad_schema=True)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert report["verdict"] == "fail"
    checks = _checks(report)
    assert checks["scan_requires_body"]["status"] == "fail"
    assert checks["scan_rejects_unknown_fields"]["status"] == "fail"


def test_preflight_fails_when_the_node_engine_is_unusable() -> None:
    node = FakeNode(enforce_auth=True, degraded_engine=True)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert report["verdict"] == "fail"
    engine = _checks(report)["engine"]
    assert engine["status"] == "fail"
    assert "requests" in engine["detail"]
    assert _checks(report)["health_contract"]["status"] == "pass"


def test_preflight_reports_a_rejected_token() -> None:
    node = FakeNode(reject_token=True)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert report["verdict"] == "fail"
    assert "rejected" in _checks(report)["reachable"]["detail"]


def test_preflight_warns_when_the_node_does_not_enforce_authentication() -> None:
    node = FakeNode(enforce_auth=False)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert report["verdict"] == "warn"
    assert _checks(report)["auth_enforced"]["status"] == "warn"
    assert _checks(report)["reachable"]["status"] == "pass"


def test_preflight_reports_an_unreachable_node_instead_of_raising() -> None:
    def refused(request):
        raise httpx.ConnectError("connection refused", request=request)

    report = verify_remote_node(node_config(), transport=httpx.MockTransport(refused))
    assert report["verdict"] == "fail"
    assert _checks(report)["reachable"]["status"] == "fail"
    assert "could not reach" in _checks(report)["reachable"]["detail"]


def test_preflight_reports_a_missing_openapi_route_as_a_warning() -> None:
    node = FakeNode(enforce_auth=True, openapi=False)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert _checks(report)["contract"]["status"] == "warn"


def test_preflight_reports_the_closed_gate_without_probing_anything() -> None:
    """The default deployment: remote is off, and nothing is contacted."""
    calls: list[tuple[str, str]] = []

    def forbidden(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        calls.append((request.method, request.url.path))
        raise AssertionError("a disabled deployment must not open a connection")

    report = verify_remote_node(RemoteNodeConfig(),
                                transport=httpx.MockTransport(forbidden))
    assert report["verdict"] == "fail"
    assert report["ok"] is False
    assert report["remote"]["enabled"] is False
    assert report["remote"]["configured"] is False
    assert _checks(report)["enabled"]["status"] == "fail"
    assert "CHAIN_GUARD_REMOTE_ENABLED" in _checks(report)["enabled"]["detail"]
    assert calls == []


def test_preflight_fails_when_enabled_but_unconfigured() -> None:
    report = verify_remote_node(RemoteNodeConfig(enabled=True))
    assert report["verdict"] == "fail"
    assert report["remote"]["enabled"] is True
    assert report["remote"]["configured"] is False
    assert _checks(report)["enabled"]["status"] == "pass"
    assert _checks(report)["configured"]["status"] == "fail"


def test_preflight_fails_on_a_malformed_url_without_probing() -> None:
    node = FakeNode()
    report = verify_remote_node(node_config(url="ftp://host:8010"), transport=node.transport())
    assert report["verdict"] == "fail"
    assert node.requests == [], "an unusable URL must not be probed"


def test_preflight_warns_when_a_remote_node_is_addressed_over_plain_http() -> None:
    node = FakeNode(enforce_auth=True)
    report = verify_remote_node(node_config(url="http://192.168.1.50:8010"),
                         transport=node.transport())
    assert _checks(report)["configured"]["status"] == "warn"


def test_preflight_reports_an_unreadable_token_file() -> None:
    config = RemoteNodeConfig(enabled=True, url="http://127.0.0.1:8010",
                        token_error="could not read the remote node token file (FileNotFoundError)")
    report = verify_remote_node(config, transport=FakeNode().transport())
    assert report["verdict"] == "fail"
    assert _checks(report)["token"]["status"] == "fail"


def test_preflight_never_discloses_the_token() -> None:
    node = FakeNode(enforce_auth=True)
    report = verify_remote_node(node_config(), transport=node.transport())
    assert TOKEN not in json.dumps(report)
    assert report["remote"]["auth"] == "token"
    assert _checks(report)["secret_hygiene"]["status"] == "pass"
    assert TOKEN not in repr(node_config())


def test_preflight_swallows_a_token_that_reaches_a_detail_string() -> None:
    """Defence in depth: even a deliberate leak is redacted before returning."""
    node = FakeNode(enforce_auth=True)
    original = remote_module.RemoteNodeClient.json_of

    def leaky(self, response, path):  # pragma: no cover - patched behaviour
        payload = original(self, response, path)
        if path == "/health":
            payload["engine"]["path"] = f"/node/{TOKEN}/engine"
        return payload

    remote_module.RemoteNodeClient.json_of = leaky
    try:
        report = verify_remote_node(node_config(), transport=node.transport())
    finally:
        remote_module.RemoteNodeClient.json_of = original
    assert TOKEN not in json.dumps(report)
    assert remote_module.REDACTED in json.dumps(report)
    assert _checks(report)["secret_hygiene"]["status"] == "warn"
    assert report["verdict"] == "warn"


def test_preflight_runs_a_real_scan_only_when_asked() -> None:
    node = FakeNode(enforce_auth=True)
    report = verify_remote_node(node_config(), transport=node.transport(),
                         probe_repository="/node/repos/app")
    probe = _checks(report)["scan_probe"]
    assert probe["status"] == "pass"
    assert "3 advisories" in probe["detail"]
    assert report["scan_probe"]["summary"]["total_vulnerabilities"] == 3
    assert report["scan_probe"]["repository"]["id"] == remote_module.PROBE_REPOSITORY_ID


def test_preflight_probe_fails_on_a_node_that_cannot_scan() -> None:
    node = FakeNode(enforce_auth=True, scan_status=503,
                    scan_body={"error": {"code": "ENGINE_UNAVAILABLE",
                                         "message": "node engine missing"}})
    report = verify_remote_node(node_config(), transport=node.transport(),
                         probe_repository="/node/repos/app")
    probe = _checks(report)["scan_probe"]
    assert probe["status"] == "fail"
    assert "node engine missing" in probe["detail"]


def test_scan_remote_fails_clearly_when_httpx_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(remote_module, "httpx", None)
    outcome = scan_remote("repo-a", "/node/repos/app", {}, node_config())
    assert outcome.http_status == 503
    assert outcome.result["error"]["code"] == "REMOTE_CLIENT_UNAVAILABLE"
    assert "httpx" in outcome.result["error"]["message"]


# ------------------------------------------------------- client / contract

def test_fetch_scan_rejects_a_non_canonical_payload() -> None:
    for body in ({"status": "completed"},            # missing required fields
                 ["not", "an", "object"],            # wrong JSON type
                 "not json at all",                  # not JSON
                 canonical_scan_payload({"id": "repo-a", "path": "/node/repos/app"},
                                        extra_body={"unexpected_top_level": 1})):
        node = FakeNode(scan_body=body)
        client = remote_module.RemoteNodeClient(node_config(), transport=node.transport())
        with pytest.raises(remote_module.RemoteError) as excinfo:
            fetch_scan(client, repository_id="repo-a", repository_path="/node/repos/app")
        assert excinfo.value.code == REMOTE_INVALID_RESPONSE
        assert excinfo.value.http_status == 502


def test_fetch_scan_relays_the_node_error_and_maps_the_status() -> None:
    cases = [
        (503, {"error": {"code": "ENGINE_UNAVAILABLE", "message": "node engine missing"}},
         "REMOTE_ENGINE_UNAVAILABLE", 503),
        (504, {"error": {"code": "SCAN_TIMEOUT", "message": "node scan timed out"}},
         "REMOTE_TIMEOUT", 504),
        (400, {"error": {"code": "INVALID_REPOSITORY", "message": "node rejected the path"}},
         "REMOTE_REQUEST_REJECTED", 400),
        (401, {"detail": "unauthorized"}, "REMOTE_AUTH_REJECTED", 502),
        (404, {"detail": "no such route"}, "REMOTE_HTTP_ERROR", 502),
    ]
    for status, body, code, http in cases:
        node = FakeNode(scan_status=status, scan_body=body)
        client = remote_module.RemoteNodeClient(node_config(), transport=node.transport())
        with pytest.raises(remote_module.RemoteError) as excinfo:
            fetch_scan(client, repository_id="repo-a", repository_path="/node/repos/app")
        assert excinfo.value.code == code, (status, body)
        assert excinfo.value.http_status == http


def test_fetch_scan_refuses_to_follow_a_redirect() -> None:
    def redirect(request):
        return httpx.Response(307, headers={"location": "http://elsewhere/scan"})

    client = remote_module.RemoteNodeClient(node_config(), transport=httpx.MockTransport(redirect))
    with pytest.raises(remote_module.RemoteError) as excinfo:
        fetch_scan(client, repository_id="repo-a", repository_path="/node/repos/app")
    assert excinfo.value.code == "REMOTE_HTTP_ERROR"
    assert "redirect" in excinfo.value.message


def test_fetch_scan_times_out_with_the_canonical_timeout_semantics() -> None:
    def slow(request):
        raise httpx.ReadTimeout("too slow", request=request)

    client = remote_module.RemoteNodeClient(node_config(), transport=httpx.MockTransport(slow))
    with pytest.raises(remote_module.RemoteError) as excinfo:
        fetch_scan(client, repository_id="repo-a", repository_path="/node/repos/app")
    assert excinfo.value.code == REMOTE_TIMEOUT
    assert excinfo.value.http_status == 504
    assert excinfo.value.state == "TIMEOUT"
    assert excinfo.value.status == "timeout"


def test_scan_remote_returns_the_nodes_payload_with_our_provenance() -> None:
    node = FakeNode()
    outcome = scan_remote("repo-a", "/node/repos/app", {"no_llm": True}, node_config(),
                          transport=node.transport())
    result = outcome.result
    assert outcome.http_status == 200
    assert result["summary"]["total_vulnerabilities"] == 3
    assert result["execution"]["mode"] == "remote"
    assert result["execution"]["node"] == "friends-laptop"
    assert result["execution"]["remote_scan_id"] == "a" * 32
    assert result["execution"]["artifacts_remote"] is True
    assert result["artifacts"] is None
    assert "written on that machine" in result["execution"]["note"]
    assert result["scan_id"] == "a" * 32
    # the node's own "local" provenance is replaced, never forwarded
    assert result["execution"]["artifacts_remote"] is not False


def test_scan_remote_sends_a_canonical_request_body() -> None:
    node = FakeNode()

    def capture(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/scan":
            body = json.loads(request.content)
            assert set(body) == {"repository", "options"}
            assert body["repository"] == {"id": "repo-a", "path": "/node/repos/app"}
            assert body["options"] == {"no_llm": False, "fail_on_actionable": True}
            assert request.headers["authorization"] == f"Bearer {TOKEN}"
        return node.handler(request)

    scan_remote("repo-a", "/node/repos/app",
                {"no_llm": False, "fail_on_actionable": True, "execution_mode": "remote"},
                node_config(), transport=httpx.MockTransport(capture))


def test_scan_remote_normalises_a_windows_style_remote_path() -> None:
    seen: list[str] = []
    node = FakeNode()

    def capture(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/scan" and request.method == "POST":
            seen.append(json.loads(request.content)["repository"]["path"])
        return node.handler(request)

    scan_remote("repo-a", "C:\\repos\\app\\.\\", {}, node_config(),
                transport=httpx.MockTransport(capture))
    assert seen == ["C:/repos/app"]


# ---------------------------------------------------------- API integration

def _remote_body(repo_id: str, path: str, mode: str = "remote") -> dict:
    return {"repository": {"id": repo_id, "path": path},
            "options": {"execution_mode": mode}}


def test_remote_scan_runs_on_the_node_and_not_locally(settings, allowed_root) -> None:
    guard = LocalEngineGuard()
    node = FakeNode()
    app = create_app(settings=remote_settings(settings, config=node_config()),
                     runner=guard, remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
    assert response.status_code == 200, response.text
    payload = response.json()
    assert guard.calls == 0, "the local engine must not run for a remote scan"
    assert payload["execution"]["mode"] == "remote"
    assert payload["execution"]["node"] == "friends-laptop"
    assert payload["execution"]["artifacts_remote"] is True
    assert payload["artifacts"] is None
    assert payload["summary"]["actionable"] == 1
    assert payload["vulnerabilities"][0]["evidence"]["vulnerable_functions"] == ["demo_fn"]
    assert ("POST", "/scan") in node.requests


def test_remote_scan_does_not_require_a_local_engine(fake_engine, allowed_root, settings) -> None:
    """A node-only deployment must still be able to serve remote scans."""
    absent = remote_settings(settings, config=node_config(),
                          engine_root=fake_engine.parent / "not-installed")
    guard = LocalEngineGuard()
    node = FakeNode()
    with TestClient(create_app(settings=absent, runner=guard,
                               remote_transport=node.transport())) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
    assert response.status_code == 200, response.text
    assert response.json()["execution"]["mode"] == "remote"
    assert guard.calls == 0


def test_remote_scan_fails_closed_while_the_gate_is_closed(settings) -> None:
    """The default deployment: no node, gate off, and no local fallback."""
    guard = LocalEngineGuard()
    app = create_app(settings=remote_settings(settings, mode="local"), runner=guard)
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
    assert response.status_code == 503
    payload = response.json()
    assert payload["error"]["code"] == REMOTE_EXECUTION_DISABLED
    assert "CHAIN_GUARD_REMOTE_ENABLED" in payload["error"]["message"]
    assert payload["status"] == "failed"
    # it says "remote" even though it failed: the caller must not be told the
    # scan happened here.
    assert payload["execution"]["mode"] == "remote"
    assert payload["execution"]["artifacts_remote"] is False
    assert guard.calls == 0, "a remote request must never fall back to a local scan"


def test_remote_scan_fails_closed_when_enabled_but_unconfigured(settings) -> None:
    guard = LocalEngineGuard()
    app = create_app(settings=remote_settings(settings, mode="local",
                                            config=RemoteNodeConfig(enabled=True)),
                     runner=guard)
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == REMOTE_EXECUTION_NOT_CONFIGURED
    assert guard.calls == 0


def test_remote_scan_rejects_a_path_outside_the_declared_root(settings) -> None:
    guard = LocalEngineGuard()
    node = FakeNode()
    config = node_config(allowed_root="/node/repos")
    app = create_app(settings=remote_settings(settings, config=config), runner=guard,
                     remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/etc/passwd"))
    assert response.status_code == 400
    assert response.json()["error"]["code"] == REMOTE_PATH_NOT_ALLOWED
    assert node.requests == [], "a refused path must not be sent to the node"
    assert guard.calls == 0


def test_remote_scan_maps_remote_failures_to_http_statuses(settings) -> None:
    cases = [
        (FakeNode(scan_status=504, scan_body={"error": {"code": "SCAN_TIMEOUT",
                                                        "message": "node timed out"}}),
         504, "REMOTE_TIMEOUT", "timeout"),
        (FakeNode(scan_status=503, scan_body={"error": {"code": "ENGINE_UNAVAILABLE",
                                                        "message": "node engine missing"}}),
         503, "REMOTE_ENGINE_UNAVAILABLE", "failed"),
        (FakeNode(scan_body={"nonsense": True}), 502, REMOTE_INVALID_RESPONSE, "failed"),
        (FakeNode(scan_status=422, scan_body={"detail": []}), 400, REMOTE_REQUEST_REJECTED, "failed"),
    ]
    for node, http, code, status in cases:
        guard = LocalEngineGuard()
        app = create_app(settings=remote_settings(settings, config=node_config()),
                         runner=guard, remote_transport=node.transport())
        with TestClient(app) as client:
            response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
        assert response.status_code == http, (code, response.text)
        payload = response.json()
        assert payload["error"]["code"] == code
        assert payload["status"] == status
        assert payload["execution"]["mode"] == "remote"
        assert guard.calls == 0


def test_remote_scan_timeout_keeps_the_api_timeout_state(settings) -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    guard = LocalEngineGuard()
    app = create_app(settings=remote_settings(settings, config=node_config()), runner=guard,
                     remote_transport=httpx.MockTransport(slow))
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
    assert response.status_code == 504
    assert response.json()["state"] == "TIMEOUT"


def test_local_scan_is_unchanged_when_a_node_is_configured(settings, allowed_root) -> None:
    node = FakeNode()
    app = create_app(settings=remote_settings(settings, config=node_config()),
                     runner=fake_runner(), remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", str(allowed_root / "repo-a"),
                                                         mode="local"))
    assert response.status_code == 200
    payload = response.json()
    assert payload["execution"]["mode"] == "local"
    assert payload["execution"]["node"] is None
    assert payload["artifacts"]["report"]
    assert node.requests == [], "a local scan must not contact the node"


def test_default_execution_mode_comes_from_the_deployment(settings, allowed_root) -> None:
    """With execution_mode=remote as the default, a plain scan uses the node."""
    guard = LocalEngineGuard()
    node = FakeNode()
    app = create_app(settings=remote_settings(settings, config=node_config(), mode="remote"),
                     runner=guard, remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.post("/scan", json={
            "repository": {"id": "repo-a", "path": "/node/repos/app"}})
    assert response.status_code == 200
    assert response.json()["execution"]["mode"] == "remote"
    assert guard.calls == 0


def test_remote_fleet_scans_every_repository_on_the_node(settings) -> None:
    guard = LocalEngineGuard()
    node = FakeNode()
    app = create_app(settings=remote_settings(settings, config=node_config()), runner=guard,
                     remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.post("/scan/fleet", json={
            "repositories": [{"id": "repo-a", "path": "/node/repos/a"},
                             {"id": "repo-b", "path": "/node/repos/b"}],
            "options": {"execution_mode": "remote"}})
    assert response.status_code == 200
    fleet = response.json()
    assert fleet["status"] == "completed"
    assert fleet["summary"]["total_repositories"] == 2
    assert fleet["summary"]["total_vulnerabilities"] == 6
    assert [r["execution"]["mode"] for r in fleet["results"]] == ["remote", "remote"]
    assert [r["scan_id"] for r in fleet["results"]] == ["a" * 32, "a" * 32]
    assert guard.calls == 0


def test_remote_fleet_does_not_need_the_local_engine(fake_engine, allowed_root, settings) -> None:
    guard = LocalEngineGuard()
    node = FakeNode()
    absent = remote_settings(settings, config=node_config(),
                           engine_root=fake_engine.parent / "gone")
    with TestClient(create_app(settings=absent, runner=guard,
                               remote_transport=node.transport())) as client:
        response = client.post("/scan/fleet", json={
            "repositories": [{"id": "repo-a", "path": "/node/repos/a"}],
            "options": {"execution_mode": "remote"}})
    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert guard.calls == 0


def test_fleet_isolates_one_failing_remote_repository(settings) -> None:
    guard = LocalEngineGuard()

    def selective(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/scan" and request.method == "POST":
            body = json.loads(request.content)
            if body["repository"]["id"] == "repo-b":
                return httpx.Response(503, json={"error": {"code": "ENGINE_UNAVAILABLE",
                                                           "message": "busy"}})
        return FakeNode().handler(request)

    app = create_app(settings=remote_settings(settings, config=node_config()), runner=guard,
                     remote_transport=httpx.MockTransport(selective))
    with TestClient(app) as client:
        fleet = client.post("/scan/fleet", json={
            "repositories": [{"id": "repo-a", "path": "/node/repos/a"},
                             {"id": "repo-b", "path": "/node/repos/b"}],
            "options": {"execution_mode": "remote"}}).json()
    assert fleet["status"] == "partial"
    assert fleet["results"][0]["status"] == "completed"
    assert fleet["results"][1]["error"]["code"] == "REMOTE_ENGINE_UNAVAILABLE"
    assert fleet["results"][1]["execution"]["mode"] == "remote"
    assert guard.calls == 0


def test_remote_preflight_endpoint_reports_without_scanning(settings) -> None:
    node = FakeNode(enforce_auth=True)
    app = create_app(settings=remote_settings(settings, config=node_config()),
                     remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.get("/remote")
    assert response.status_code == 200
    report = response.json()
    assert report["verdict"] == "pass"
    assert report["remote"]["auth"] == "token"
    assert TOKEN not in response.text
    assert report["scan_probe"] is None


def test_health_discloses_the_node_without_probing_it(settings) -> None:
    node = FakeNode()
    app = create_app(settings=remote_settings(settings, config=node_config()),
                     remote_transport=node.transport())
    with TestClient(app) as client:
        payload = client.get("/health").json()
    assert payload["status"] == "ok"
    assert payload["remote"]["configured"] is True
    assert payload["remote"]["node"] == "friends-laptop"
    assert payload["remote"]["auth"] == "token"
    assert node.requests == [], "a health check must not depend on the node"


def test_health_degrades_when_remote_is_the_default_but_no_node_is_set(settings) -> None:
    app = create_app(settings=remote_settings(settings, mode="remote"))
    with TestClient(app) as client:
        payload = client.get("/health").json()
    assert payload["status"] == "degraded"
    assert payload["remote"]["configured"] is False


def test_openapi_still_exposes_the_canonical_routes(settings) -> None:
    app = create_app(settings=remote_settings(settings))
    schema = app.openapi()
    assert set(schema["paths"]) >= {"/health", "/scan", "/scan/fleet", "/remote"}


# ------------------------------------------------------------------ config

def test_settings_read_the_remote_configuration_from_the_environment(fake_engine,
                                                                  allowed_root, tmp_path) -> None:
    token_file = tmp_path / "remote.token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    env = {
        "CHAIN_GUARD_ENGINE_ROOT": str(fake_engine),
        "CHAIN_GUARD_ALLOWED_ROOT": str(allowed_root),
        "CHAIN_GUARD_SCAN_WORKSPACE": str(allowed_root / "ws"),
        "CHAIN_GUARD_EXECUTION_MODE": "remote",
        "CHAIN_GUARD_REMOTE_ENABLED": "true",
        "CHAIN_GUARD_REMOTE_URL": "https://node.internal:8010/",
        "CHAIN_GUARD_REMOTE_TOKEN_FILE": str(token_file),
        "CHAIN_GUARD_REMOTE_LABEL": "friends-laptop",
        "CHAIN_GUARD_REMOTE_ALLOWED_ROOT": "/node/repos",
        "CHAIN_GUARD_REMOTE_TIMEOUT_SECONDS": "45",
    }
    built = Settings.from_env(env)
    assert built.execution_mode == "remote"
    assert built.remote.enabled is True
    assert built.remote.configured is True
    assert built.remote.base_url == "https://node.internal:8010"
    assert built.remote.token == TOKEN
    assert built.remote.timeout_seconds == 45
    assert built.remote.label == "friends-laptop"
    assert built.remote.allowed_root == "/node/repos"
    assert TOKEN not in repr(built.remote)
    assert built.remote.redacted()["auth"] == "token"


def test_settings_default_to_local_with_no_node(fake_engine, allowed_root) -> None:
    built = Settings.from_env({"CHAIN_GUARD_ENGINE_ROOT": str(fake_engine),
                               "CHAIN_GUARD_ALLOWED_ROOT": str(allowed_root),
                               "CHAIN_GUARD_SCAN_WORKSPACE": str(allowed_root / "ws"),
                               "CHAIN_GUARD_EXECUTION_MODE": "sideways"})
    assert built.execution_mode == "local"
    # the gate is closed unless it is asked for: this is the default deployment
    assert built.remote.enabled is False
    assert built.remote.configured is False


def test_settings_report_an_unreadable_token_file(fake_engine, allowed_root, tmp_path) -> None:
    built = Settings.from_env({
        "CHAIN_GUARD_ENGINE_ROOT": str(fake_engine),
        "CHAIN_GUARD_ALLOWED_ROOT": str(allowed_root),
        "CHAIN_GUARD_SCAN_WORKSPACE": str(allowed_root / "ws"),
        "CHAIN_GUARD_REMOTE_URL": "http://127.0.0.1:8010",
        "CHAIN_GUARD_REMOTE_TOKEN_FILE": str(tmp_path / "absent.token"),
    })
    assert built.remote.token is None
    assert built.remote.token_error


def test_the_engine_environment_is_never_told_about_the_node(settings, allowed_root) -> None:
    """execution_mode is an API concern; it must not leak into the CLI command."""
    seen: list[list[str]] = []

    def runner(command, cwd, timeout):
        seen.append(list(command))
        return fake_runner()(command, cwd, timeout)

    node = FakeNode()
    app = create_app(settings=remote_settings(settings, config=node_config()), runner=runner,
                     remote_transport=node.transport())
    with TestClient(app) as client:
        client.post("/scan", json=_remote_body("repo-a", str(allowed_root / "repo-a"),
                                              mode="local"))
    assert seen
    assert not [part for part in seen[0] if "execution" in part or "remote" in part]


def test_remote_check_cli_exits_nonzero_on_a_failed_preflight(capsys) -> None:
    """Nothing listens on port 1, so this is a real (refused) connection."""
    from chainguard_api import remote_check

    code = remote_check.main(["--url", "http://127.0.0.1:1", "--health-timeout", "0.5",
                            "--enable", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["verdict"] == "fail"
    assert report["remote"]["enabled"] is True
    assert report["remote"]["configured"] is True


def test_remote_check_cli_passes_with_a_conforming_node(monkeypatch, capsys) -> None:
    from chainguard_api import remote_check

    node = FakeNode(enforce_auth=True)
    calls: list[dict] = []

    def fake_verify(config, **kwargs):
        calls.append(kwargs)
        return verify_remote_node(config, transport=node.transport(), **kwargs)

    monkeypatch.setenv("CHAIN_GUARD_TEST_TOKEN", TOKEN)
    monkeypatch.setattr(remote_check, "verify_remote_node", fake_verify)
    code = remote_check.main(["--url", "http://127.0.0.1:8010", "--enable",
                              "--token-env", "CHAIN_GUARD_TEST_TOKEN"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "VERDICT: pass" in out
    assert TOKEN not in out
    assert calls and calls[0].get("probe_repository") is None


def test_remote_check_cli_reads_the_token_from_the_environment(monkeypatch, capsys) -> None:
    from chainguard_api import remote_check

    node = FakeNode(enforce_auth=True)
    monkeypatch.setenv("CHAIN_GUARD_TEST_TOKEN", TOKEN)
    seen: list[RemoteNodeConfig] = []

    def capture(config, **kwargs):
        seen.append(config)
        return verify_remote_node(config, transport=node.transport(), **kwargs)

    monkeypatch.setattr(remote_check, "verify_remote_node", capture)
    assert remote_check.main(["--url", "http://127.0.0.1:8010", "--enable",
                            "--token-env", "CHAIN_GUARD_TEST_TOKEN"]) == 0
    assert seen[0].token == TOKEN
    assert TOKEN not in capsys.readouterr().out


def test_remote_check_cli_reports_the_closed_gate(capsys) -> None:
    """With no --enable and no URL, the report itself explains the state."""
    from chainguard_api import remote_check

    assert remote_check.main([]) == 1
    out = capsys.readouterr().out
    assert "remote execution is disabled" in out.lower()
    assert "nothing was probed" in out


def test_remote_check_cli_requires_a_url_once_enabled(capsys) -> None:
    from chainguard_api import remote_check

    assert remote_check.main(["--enable"]) == 2
    assert "no node URL was given" in capsys.readouterr().err


def test_remote_check_cli_is_strict_on_request(monkeypatch, capsys) -> None:
    """A token is configured but the node ignores it: usable, but only with --strict"."""
    from chainguard_api import remote_check

    node = FakeNode(enforce_auth=False)
    monkeypatch.setenv("CHAIN_GUARD_TEST_TOKEN", TOKEN)
    monkeypatch.setattr(remote_check, "verify_remote_node",
                        lambda config, **kwargs: verify_remote_node(config,
                                                             transport=node.transport(),
                                                             **kwargs))
    args = ["--url", "http://127.0.0.1:8010", "--enable",
            "--token-env", "CHAIN_GUARD_TEST_TOKEN"]
    assert remote_check.main(args) == 0
    assert "VERDICT: usable with warnings" in capsys.readouterr().out
    assert remote_check.main(args + ["--strict"]) == 1


def test_remote_module_has_no_hardcoded_secrets_or_developer_paths() -> None:
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for name in ("remote.py", "remote_check.py", "config.py"):
        text = (root / name).read_text(encoding="utf-8")
        for needle in ("C:\\Users", "/Users/", "mahesh", "/home/"):
            assert needle not in text, f"{name}: {needle}"


def test_a_disabled_deployment_makes_no_outbound_call_from_any_entry_point(
        settings, allowed_root, monkeypatch, capsys) -> None:
    """The gate is not decorative: while it is closed nothing can connect.

    Every entry point that could reach a node is exercised with HTTP client
    construction replaced by a stub that fails the test if a connection is ever
    set up. /health, /remote, local /scan, local /scan/fleet and the CLI must
    all work -- and a remote request must be refused -- without constructing a
    single client.
    """
    attempts: list[str] = []

    def forbidden_client(*args, **kwargs):  # pragma: no cover - must not run
        attempts.append("httpx.Client()")
        raise AssertionError("a disabled deployment constructed an HTTP client")

    monkeypatch.setattr(remote_module.httpx, "Client", forbidden_client)
    monkeypatch.delenv("CHAIN_GUARD_REMOTE_ENABLED", raising=False)
    closed = node_config(enabled=False)
    app = create_app(settings=remote_settings(settings, config=closed),
                     runner=fake_runner(), remote_transport=None)
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        preflight = client.get("/remote")
        assert preflight.status_code == 200
        assert preflight.json()["verdict"] == "fail"
        local = client.post("/scan", json=_remote_body("repo-a", str(allowed_root / "repo-a"),
                                                      mode="local"))
        assert local.status_code == 200
        assert local.json()["execution"]["mode"] == "local"
        fleet = client.post("/scan/fleet", json={
            "repositories": [{"id": "repo-a", "path": str(allowed_root / "repo-a")}]})
        assert fleet.status_code == 200
        # a remote request is refused without touching the network
        refused = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == REMOTE_EXECUTION_DISABLED

    from chainguard_api import remote_check

    code = remote_check.main(["--url", "http://127.0.0.1:8010", "--json"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["remote"]["enabled"] is False
    assert attempts == [], attempts


def test_local_mode_is_unaffected_while_the_gate_is_closed(settings, allowed_root) -> None:
    node = FakeNode()
    closed = node_config(enabled=False)
    app = create_app(settings=remote_settings(settings, config=closed),
                     runner=fake_runner(), remote_transport=node.transport())
    with TestClient(app) as client:
        payload = client.post("/scan", json=_remote_body(
            "repo-a", str(allowed_root / "repo-a"), mode="local")).json()
    assert payload["execution"]["mode"] == "local"
    assert payload["artifacts"]["report"]
    assert node.requests == [], "a local scan must not contact the node"


def test_health_reports_the_closed_gate(settings) -> None:
    app = create_app(settings=remote_settings(settings))
    with TestClient(app) as client:
        payload = client.get("/health").json()
    assert payload["status"] == "ok"
    assert payload["remote"]["enabled"] is False
    assert payload["remote"]["configured"] is False


@pytest.mark.parametrize("raw, expected", [
    ("true", True), ("1", True), ("yes", True), ("on", True),
    ("false", False), ("0", False), ("no", False), ("", False),
])
def test_the_gate_is_read_from_the_environment(fake_engine, allowed_root, raw, expected) -> None:
    built = Settings.from_env({
        "CHAIN_GUARD_ENGINE_ROOT": str(fake_engine),
        "CHAIN_GUARD_ALLOWED_ROOT": str(allowed_root),
        "CHAIN_GUARD_SCAN_WORKSPACE": str(allowed_root / "ws"),
        "CHAIN_GUARD_REMOTE_ENABLED": raw,
        "CHAIN_GUARD_REMOTE_URL": "http://127.0.0.1:8010",
    })
    assert built.remote.enabled is expected
    assert built.remote.configured is expected


def test_remote_scan_keeps_unknown_evidence_fields(settings) -> None:
    """The remote path must not drop evidence the node sent (extra=allow)."""
    payload = canonical_scan_payload({"id": "repo-a", "path": "/node/repos/app"})
    payload["vulnerabilities"][0]["evidence"]["future_signal"] = {"score": 7}
    payload["vulnerabilities"][0]["future_vulnerability_field"] = "kept"
    payload["summary"]["future_summary_field"] = 3
    node = FakeNode(scan_body=payload)
    guard = LocalEngineGuard()
    app = create_app(settings=remote_settings(settings, config=node_config()), runner=guard,
                     remote_transport=node.transport())
    with TestClient(app) as client:
        response = client.post("/scan", json=_remote_body("repo-a", "/node/repos/app"))
    body = response.json()
    assert body["vulnerabilities"][0]["evidence"]["future_signal"] == {"score": 7}
    assert body["vulnerabilities"][0]["future_vulnerability_field"] == "kept"
    assert body["summary"]["future_summary_field"] == 3
    assert guard.calls == 0

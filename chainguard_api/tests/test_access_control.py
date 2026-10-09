"""Access control for a publicly reachable deployment.

These tests run the real FastAPI app through TestClient with a controlled
runner (no engine subprocess for the scan path) and assert the observable
contract: who gets through, what an anonymous caller can learn, and that a
bad token fails closed.
"""
from __future__ import annotations

import dataclasses
import json

import pytest
from fastapi.testclient import TestClient

from chainguard_api.app import create_app
from chainguard_api.auth import bearer_matches
from chainguard_api.config import Settings
from conftest import fake_runner

TOKEN = "test-token-7f3a9c"
SCAN_ID = "a" * 32


def _secured(settings: Settings, **overrides) -> Settings:
    return dataclasses.replace(settings, api_token=TOKEN, **overrides)


def _scan_body(allowed_root) -> dict:
    return {"repository": {"id": "repo-a", "path": str(allowed_root / "repo-a")}}


def test_scan_requires_the_token_when_one_is_configured(settings, allowed_root) -> None:
    app = create_app(settings=_secured(settings), runner=fake_runner())
    with TestClient(app) as client:
        anonymous = client.post("/scan", json=_scan_body(allowed_root))
        wrong = client.post("/scan", json=_scan_body(allowed_root),
                            headers={"Authorization": "Bearer not-the-token"})
        scheme = client.post("/scan", json=_scan_body(allowed_root),
                             headers={"Authorization": f"Basic {TOKEN}"})
        allowed = client.post("/scan", json=_scan_body(allowed_root),
                              headers={"Authorization": f"Bearer {TOKEN}"})
    for denied in (anonymous, wrong, scheme):
        assert denied.status_code == 401, denied.text
        assert denied.json()["detail"]["code"] == "UNAUTHORIZED"
        assert denied.headers["www-authenticate"] == "Bearer"
        assert TOKEN not in denied.text
    assert allowed.status_code == 200, allowed.text


def test_scan_is_open_when_no_token_is_configured(settings, allowed_root) -> None:
    app = create_app(settings=settings, runner=fake_runner())
    with TestClient(app) as client:
        response = client.post("/scan", json=_scan_body(allowed_root))
    assert response.status_code == 200, response.text


def test_artifacts_and_remote_are_protected_too(settings) -> None:
    app = create_app(settings=_secured(settings), runner=fake_runner())
    with TestClient(app) as client:
        artifact = client.get(
            f"/scans/{SCAN_ID}/repositories/repo-a/artifacts/report.json")
        remote = client.get("/remote")
        fleet = client.post("/scan/fleet", json={"repositories": [
            {"id": "repo-a", "path": "/x"}]})
    assert artifact.status_code == 401
    assert remote.status_code == 401
    assert fleet.status_code == 401


def test_anonymous_health_is_redacted(settings) -> None:
    app = create_app(settings=_secured(settings), runner=fake_runner())
    with TestClient(app) as client:
        payload = client.get("/health").json()
    assert payload["status"] in {"ok", "degraded"}
    assert payload["auth"] == {"required": True}
    assert set(payload["engine"]) == {"available", "implementation"}
    assert "remote" not in payload
    assert "path" not in json.dumps(payload)


def test_authorized_health_keeps_the_full_disclosure(settings) -> None:
    app = create_app(settings=_secured(settings), runner=fake_runner())
    with TestClient(app) as client:
        payload = client.get("/health", headers={"Authorization": f"Bearer {TOKEN}"}).json()
    assert payload["auth"] == {"required": True}
    assert "path" in payload["engine"]
    assert "remote" in payload


def test_open_health_reports_auth_not_required(settings) -> None:
    app = create_app(settings=settings, runner=fake_runner())
    with TestClient(app) as client:
        payload = client.get("/health").json()
    assert payload["auth"] == {"required": False}
    assert "path" in payload["engine"]


def test_api_docs_are_not_served_when_a_token_is_configured(settings) -> None:
    secured = TestClient(create_app(settings=_secured(settings), runner=fake_runner()))
    open_app = TestClient(create_app(settings=settings, runner=fake_runner()))
    with secured:
        assert secured.get("/openapi.json").status_code == 404
        assert secured.get("/docs").status_code == 404
    with open_app:
        assert open_app.get("/openapi.json").status_code == 200


def test_oversized_request_is_refused_before_it_is_read(settings, allowed_root) -> None:
    app = create_app(settings=dataclasses.replace(settings, max_request_bytes=64),
                     runner=fake_runner())
    body = json.dumps(_scan_body(allowed_root) | {"padding": "x" * 200})
    with TestClient(app) as client:
        response = client.post("/scan", content=body,
                               headers={"Content-Type": "application/json"})
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "REQUEST_TOO_LARGE"


def test_bearer_matching_is_strict() -> None:
    assert bearer_matches(f"Bearer {TOKEN}", TOKEN)
    assert bearer_matches(f"Bearer  {TOKEN} ", TOKEN)
    assert not bearer_matches(None, TOKEN)
    assert not bearer_matches(TOKEN, TOKEN)
    assert not bearer_matches("Bearer ", TOKEN)
    assert not bearer_matches(f"Bearer {TOKEN}x", TOKEN)


def test_token_is_loaded_from_the_environment_and_never_repr(tmp_path) -> None:
    settings = Settings.from_env({"CHAIN_GUARD_API_TOKEN": TOKEN})
    assert settings.api_token == TOKEN
    assert TOKEN not in repr(settings)


def test_token_file_is_read_and_a_broken_one_fails_closed(tmp_path) -> None:
    token_file = tmp_path / "api.token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    assert Settings.from_env({"CHAIN_GUARD_API_TOKEN_FILE": str(token_file)}).api_token == TOKEN

    empty = tmp_path / "empty.token"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(RuntimeError):
        Settings.from_env({"CHAIN_GUARD_API_TOKEN_FILE": str(empty)})
    with pytest.raises(RuntimeError):
        Settings.from_env({"CHAIN_GUARD_API_TOKEN_FILE": str(tmp_path / "missing.token")})


def test_no_token_by_default(tmp_path) -> None:
    settings = Settings.from_env({})
    assert settings.api_token is None
    assert settings.max_request_bytes == 65536

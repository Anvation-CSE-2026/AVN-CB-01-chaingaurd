"""API-level tests exercised through the real FastAPI routes."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chainguard_api.app import create_app
from chainguard_api.config import Settings
from chainguard_api.schemas import FleetResponse, HealthResponse, RepositoryResult, ScanRequest
from conftest import Tracker, fake_runner, report_payload

pytestmark = []


def _client(settings: Settings, runner=None) -> TestClient:
    return TestClient(create_app(settings=settings, runner=runner))


def _scan_body(allowed_root: Path, repo_id: str) -> dict:
    return {"repository": {"id": repo_id, "path": str(allowed_root / repo_id)}}


# ---------------------------------------------------------------- health

def test_health_reports_real_engine_available(settings) -> None:
    with _client(settings) as client:
        response = client.get("/health")
    assert response.status_code == 200
    payload = HealthResponse.model_validate(response.json())
    assert payload.status == "ok"
    assert payload.engine.available is True
    assert payload.engine.implementation == "real"
    assert payload.engine.type == "real"
    assert payload.engine.entrypoint == "chainguard_mvp.cli"
    assert payload.engine.path and payload.engine.path.endswith("engine")


def test_health_degrades_when_engine_missing(fake_engine, allowed_root) -> None:
    settings = Settings(engine_root=fake_engine.parent / "absent",
                        allowed_root=allowed_root,
                        workspace_dir=allowed_root / "scan_workspace",
                        max_concurrent_scans=2, scan_timeout_seconds=5,
                        python_executable=sys.executable)
    with _client(settings) as client:
        payload = client.get("/health").json()
    assert payload["status"] == "degraded"
    assert payload["engine"]["available"] is False
    assert payload["engine"]["implementation"] == "missing"


# ---------------------------------------------------------------- /scan

def test_scan_single_repository(settings, allowed_root) -> None:
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan", json=_scan_body(allowed_root, "repo-a"))
    assert response.status_code == 200
    result = RepositoryResult.model_validate(response.json())
    assert result.status == "completed"
    assert result.state == "COMPLETED"
    assert result.summary.total_vulnerabilities == 3
    assert len(result.vulnerabilities) == 3
    assert result.vulnerabilities[0].evidence is not None
    assert result.artifacts.report and Path(result.artifacts.report).is_file()
    assert result.artifacts.sbom and Path(result.artifacts.sbom).is_file()
    assert result.artifacts.vex and Path(result.artifacts.vex).is_file()
    assert result.artifacts.trace and Path(result.artifacts.trace).is_file()


def test_scan_rejects_path_outside_allowed_root(settings, tmp_path) -> None:
    body = {"repository": {"id": "evil", "path": str(tmp_path / "outside")}}
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan", json=body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REPOSITORY"
    assert response.json()["status"] == "failed"


def test_scan_rejects_traversal_path(settings, allowed_root) -> None:
    body = {"repository": {"id": "evil", "path": str(allowed_root / ".." / "outside")}}
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan", json=body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REPOSITORY"


def test_scan_rejects_unsafe_repository_id(settings, allowed_root) -> None:
    body = {"repository": {"id": "../escape", "path": str(allowed_root / "repo-a")}}
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan", json=body)
    assert response.status_code == 422


def test_scan_returns_503_without_engine(fake_engine, allowed_root) -> None:
    settings = Settings(engine_root=fake_engine.parent / "absent",
                        allowed_root=allowed_root,
                        workspace_dir=allowed_root / "scan_workspace",
                        max_concurrent_scans=2, scan_timeout_seconds=5,
                        python_executable=sys.executable)
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan", json=_scan_body(allowed_root, "repo-a"))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ENGINE_UNAVAILABLE"


def test_scan_timeout_returns_504(settings, allowed_root) -> None:
    with _client(settings, runner=fake_runner(timeout_error=True)) as client:
        response = client.post("/scan", json=_scan_body(allowed_root, "repo-a"))
    assert response.status_code == 504
    assert response.json()["status"] == "timeout"
    assert response.json()["state"] == "TIMEOUT"


# ---------------------------------------------------------------- /scan/fleet

def test_fleet_two_valid_repositories(settings, allowed_root) -> None:
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan/fleet", json={
            "repositories": [
                {"id": "repo-a", "path": str(allowed_root / "repo-a")},
                {"id": "repo-b", "path": str(allowed_root / "repo-b")},
            ]})
    assert response.status_code == 200
    fleet = FleetResponse.model_validate(response.json())
    assert fleet.status == "completed"
    assert fleet.summary.total_repositories == 2
    assert fleet.summary.completed == 2
    assert fleet.summary.failed == 0
    assert fleet.summary.total_vulnerabilities == 6
    assert all(r.status == "completed" for r in fleet.results)
    assert fleet.scan_id


def test_fleet_five_repositories_respect_concurrency_limit(settings, allowed_root) -> None:
    assert settings.max_concurrent_scans == 2
    tracker = Tracker()
    runner = fake_runner(delay=0.15, tracker=tracker)
    repositories = [
        {"id": "repo-a", "path": str(allowed_root / "repo-a")},
        {"id": "repo-b", "path": str(allowed_root / "repo-b")},
        {"id": "repo-c", "path": str(allowed_root / "repo-c")},
        {"id": "repo-d", "path": str(allowed_root / "repo-d")},
        {"id": "repo-e", "path": str(allowed_root / "repo-e")},
    ]
    with _client(settings, runner=runner) as client:
        response = client.post("/scan/fleet", json={"repositories": repositories})
    assert response.status_code == 200
    fleet = FleetResponse.model_validate(response.json())
    assert fleet.summary.completed == 5
    assert tracker.calls == 5
    assert tracker.peak <= 2, f"unbounded concurrency observed: {tracker.peak}"


def test_fleet_isolates_invalid_repository(settings, allowed_root, tmp_path) -> None:
    repositories = [
        {"id": "repo-a", "path": str(allowed_root / "repo-a")},
        {"id": "repo-b", "path": str(tmp_path / "outside")},
        {"id": "repo-c", "path": str(allowed_root / "repo-c")},
    ]
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan/fleet", json={"repositories": repositories})
    fleet = FleetResponse.model_validate(response.json())
    assert fleet.status == "partial"
    assert fleet.summary.total_repositories == 3
    assert fleet.summary.completed == 2
    assert fleet.summary.failed == 1
    assert fleet.results[0].status == "completed"
    assert fleet.results[1].status == "failed"
    assert fleet.results[1].error.code == "INVALID_REPOSITORY"
    assert fleet.results[2].status == "completed"
    assert len(fleet.results[2].vulnerabilities) == 3   # A and C both kept


def test_fleet_isolates_timeout(settings, allowed_root) -> None:
    base = fake_runner()

    def selective(command, cwd, timeout):
        repo = str(command[3])
        if repo.endswith("repo-b"):
            return fake_runner(timeout_error=True)(command, cwd, timeout)
        return base(command, cwd, timeout)

    repositories = [
        {"id": "repo-a", "path": str(allowed_root / "repo-a")},
        {"id": "repo-b", "path": str(allowed_root / "repo-b")},
        {"id": "repo-c", "path": str(allowed_root / "repo-c")},
    ]
    with _client(settings, runner=selective) as client:
        response = client.post("/scan/fleet", json={"repositories": repositories})
    fleet = FleetResponse.model_validate(response.json())
    assert fleet.status == "partial"
    assert fleet.results[0].status == "completed"
    assert fleet.results[1].status == "timeout"
    assert fleet.results[1].error.code == "SCAN_TIMEOUT"
    assert fleet.results[2].status == "completed"
    assert fleet.summary.completed == 2
    assert fleet.summary.failed == 1


def test_fleet_aggregates_sums_without_double_counting(settings, allowed_root) -> None:
    repositories = [{"id": f"repo-{letter}", "path": str(allowed_root / f"repo-{letter}")}
                     for letter in "abc"]
    with _client(settings, runner=fake_runner()) as client:
        fleet = FleetResponse.model_validate(
            client.post("/scan/fleet", json={"repositories": repositories}).json())
    individual = [r.summary.total_vulnerabilities for r in fleet.results]
    assert fleet.summary.total_vulnerabilities == sum(individual) == 9
    assert fleet.summary.dismissed_unreachable == sum(
        r.summary.dismissed_unreachable for r in fleet.results)
    assert fleet.summary.actionable == sum(r.summary.actionable for r in fleet.results)
    assert fleet.summary.suspicious_packages == sum(
        r.summary.suspicious_packages for r in fleet.results)
    reports = {r.artifacts.report for r in fleet.results}
    assert len(reports) == 3                       # isolated outputs, no collisions


def test_fleet_returns_503_without_engine(fake_engine, allowed_root) -> None:
    settings = Settings(engine_root=fake_engine.parent / "absent",
                        allowed_root=allowed_root,
                        workspace_dir=allowed_root / "scan_workspace",
                        max_concurrent_scans=2, scan_timeout_seconds=5,
                        python_executable=sys.executable)
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan/fleet", json={
            "repositories": [{"id": "repo-a", "path": str(allowed_root / "repo-a")}]})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "ENGINE_UNAVAILABLE"


def test_fleet_rejects_traversal_repository_id(settings, allowed_root) -> None:
    with _client(settings, runner=fake_runner()) as client:
        response = client.post("/scan/fleet", json={
            "repositories": [{"id": "../../x", "path": str(allowed_root / "repo-a")}]})
    assert response.status_code == 422


# ---------------------------------------------------------------- schemas

def test_openapi_exposes_all_routes_and_models(settings) -> None:
    app = create_app(settings=settings, runner=fake_runner())
    schema = app.openapi()
    assert set(schema["paths"]) >= {"/health", "/scan", "/scan/fleet"}
    body = _scan_body(allowed_root=app.state.settings.allowed_root, repo_id="repo-a")
    request = ScanRequest.model_validate(body)
    assert request.repository.id == "repo-a"
    assert request.options.no_llm is True


def test_no_hardcoded_developer_paths_in_source() -> None:
    root = Path(__file__).resolve().parents[1]
    offenders = []
    for path in sorted(root.glob("*.py")):        # production modules only
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in ("C:\\Users", "/Users/", "mahesh", "/home/"):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == [], offenders


# ------------------------------------------------- evidence preservation

def test_unresolved_dependencies_survive_the_api_round_trip(settings, allowed_root) -> None:
    """A skipped manifest declaration must not be discarded by the API schema."""
    payload = report_payload(str(allowed_root / "repo-a"))
    payload["unresolved_dependencies"] = [
        {"name": "express", "version_specifier": ">=4.0.0", "ecosystem": "npm",
         "reason": "non_concrete_version", "file": "package.json", "raw": "express: >=4.0.0"},
        {"name": "com.example:lib", "version_specifier": "${my.version}",
         "ecosystem": "Maven", "reason": "unresolved_maven_property",
         "file": "pom.xml", "raw": "com.example:lib:${my.version}"}, ]
    with _client(settings, runner=fake_runner(report=payload)) as client:
        response = client.post("/scan", json=_scan_body(allowed_root, "repo-a"))
    result = RepositoryResult.model_validate(response.json())
    assert [d["reason"] for d in result.unresolved_dependencies] == [
        "non_concrete_version", "unresolved_maven_property"]
    assert result.unresolved_dependencies[0]["file"] == "package.json"


def test_unknown_evidence_fields_are_never_dropped(settings, allowed_root) -> None:
    """extra="allow" must really round-trip fields the schema does not model."""
    payload = report_payload(str(allowed_root / "repo-a"))
    payload["vulnerabilities"][0]["evidence"]["future_signal"] = {"score": 7}
    payload["vulnerabilities"][0]["future_vulnerability_field"] = "kept"
    payload["suspicious_packages"][0]["future_suspicious_field"] = [1, 2]
    payload["summary"]["future_summary_field"] = 3
    with _client(settings, runner=fake_runner(report=payload)) as client:
        response = client.post("/scan", json=_scan_body(allowed_root, "repo-a"))
    result = RepositoryResult.model_validate(response.json())
    assert result.vulnerabilities[0].evidence["future_signal"] == {"score": 7}
    assert result.vulnerabilities[0].model_dump()["future_vulnerability_field"] == "kept"
    assert result.suspicious_packages[0].model_dump()["future_suspicious_field"] == [1, 2]
    assert result.summary.model_dump()["future_summary_field"] == 3


def test_fleet_preserves_per_repository_disclosures(settings, allowed_root) -> None:
    def selective(command, cwd, timeout):
        payload = report_payload(str(command[3]))
        payload["unresolved_dependencies"] = [
            {"name": Path(command[3]).name, "version_specifier": ">=1.0",
             "ecosystem": "npm", "reason": "non_concrete_version",
             "file": "package.json", "raw": "x: >=1.0"}]
        return fake_runner(report=payload)(command, cwd, timeout)

    with _client(settings, runner=selective) as client:
        fleet = FleetResponse.model_validate(client.post("/scan/fleet", json={
            "repositories": [{"id": "repo-a", "path": str(allowed_root / "repo-a")},
                             {"id": "repo-b", "path": str(allowed_root / "repo-b")}]}).json())
    assert [r.unresolved_dependencies[0]["name"] for r in fleet.results] == ["repo-a", "repo-b"]

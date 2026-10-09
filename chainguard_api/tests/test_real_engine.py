"""Integration: the API must drive the REAL ChainGuard engine (no mocks).

No numbers here are fabricated: the test parses the artifacts the real scanner
wrote on disk and compares them with what the API returned, then compares the
totals with the previously observed direct-scan result (30 / 26 / 4 / 1).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chainguard_api.app import create_app
from chainguard_api.config import Settings
from chainguard_api.schemas import HealthResponse, RepositoryResult
from conftest import REAL_ENGINE_ROOT, REAL_TEST_PROJECT, WORKSPACE_ROOT

#: Result previously observed from a direct run of the real scanner against
#: software supply chain mvp/test_project.
HISTORICAL_DIRECT = {"total_vulnerabilities": 30, "dismissed_unreachable": 26,
                     "actionable": 4, "suspicious_packages": 1}

if not (REAL_ENGINE_ROOT.is_dir() and REAL_TEST_PROJECT.is_dir()):
    pytest.skip("real ChainGuard engine / test_project not present on this machine",
                allow_module_level=True)


def _settings() -> Settings:
    return Settings(
        engine_root=REAL_ENGINE_ROOT,
        allowed_root=WORKSPACE_ROOT,
        workspace_dir=WORKSPACE_ROOT / "chainguard_api" / "scan_workspace_pytest",
        max_concurrent_scans=2,
        scan_timeout_seconds=300,
        python_executable=sys.executable,
        default_no_llm=True,
    )


def test_health_confirms_real_engine() -> None:
    with TestClient(create_app(settings=_settings())) as client:
        payload = HealthResponse.model_validate(client.get("/health").json())
    assert payload.status == "ok"
    assert payload.engine.available is True
    assert payload.engine.implementation == "real"
    assert payload.engine.entrypoint == "chainguard_mvp.cli"
    assert payload.engine.path and Path(payload.engine.path, "chainguard_mvp",
                                        "cli.py").is_file()


def test_single_scan_runs_real_scanner_and_preserves_artifacts() -> dict:
    settings = _settings()
    with TestClient(create_app(settings=settings)) as client:
        response = client.post("/scan", json={
            "repository": {"id": "test-project", "path": str(REAL_TEST_PROJECT)}})
    assert response.status_code == 200, response.text

    result = RepositoryResult.model_validate(response.json())
    assert result.status in {"completed", "failed"}
    assert result.status == "completed", result.error
    assert result.scan and result.scan.exit_code == 0

    report_path = Path(result.artifacts.report)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    # 1. the API summary is exactly the scanner's summary (nothing rewritten)
    assert result.summary.model_dump() == report["summary"]
    # 2. every finding and its evidence survived the API round-trip
    assert len(result.vulnerabilities) == len(report["vulnerabilities"])
    for api_vuln, file_vuln in zip(result.vulnerabilities, report["vulnerabilities"]):
        assert api_vuln.id == file_vuln["id"]
        assert api_vuln.status == file_vuln["status"]
        assert api_vuln.evidence == file_vuln["evidence"]
        assert "vulnerable_functions" in (api_vuln.evidence or {})
    # 3. SBOM / VEX / trace are the real ones, untouched
    sbom = json.loads(Path(result.artifacts.sbom).read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    vex = json.loads(Path(result.artifacts.vex).read_text(encoding="utf-8"))
    assert "openvex.dev" in vex["@context"] and vex["statements"]
    trace = json.loads(Path(result.artifacts.trace).read_text(encoding="utf-8"))
    assert trace["stages"], "trace must contain stages"
    assert Path(result.artifacts.stdout_log).is_file()

    summary = report["summary"]
    print("\nREAL SCANNER RESULT VIA API:",
          json.dumps(summary, sort_keys=True))
    return summary


def test_result_matches_previously_observed_direct_scan() -> None:
    summary = test_single_scan_runs_real_scanner_and_preserves_artifacts()
    actual = {key: summary[key] for key in HISTORICAL_DIRECT}
    if actual != HISTORICAL_DIRECT:
        pytest.fail(
            "STOP: the API/scan result differs from the previously observed direct "
            f"scanner result.\npreviously observed: {HISTORICAL_DIRECT}\n"
            f"actual:            {actual}\n"
            "Investigate (OSV data drift vs. adapter bug) before changing anything."
        )
    assert summary["noise_reduced_percent"] == 86.7

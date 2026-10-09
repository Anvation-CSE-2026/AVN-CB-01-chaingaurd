"""Service-level tests: adapter contract, exit codes, timeouts, isolation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from chainguard_api.config import Settings
from chainguard_api.service import aggregate_fleet, default_runner, scan_repository
from conftest import fake_runner, report_payload


def _out(settings: Settings, scan_id: str, repo_id: str) -> Path:
    return settings.workspace_dir / scan_id / repo_id


def test_single_scan_completes_and_preserves_evidence(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s1", "repo-a"),
        {}, settings=settings, runner=fake_runner(), repository_id="repo-a")

    assert result["status"] == "completed"
    assert result["state"] == "COMPLETED"
    assert result["error"] is None
    assert result["summary"] == {
        "total_vulnerabilities": 3, "dismissed_unreachable": 2, "actionable": 1,
        "suspicious_packages": 1, "noise_reduced_percent": 66.7}
    assert len(result["vulnerabilities"]) == 3
    first = result["vulnerabilities"][0]
    for field in ("id", "aliases", "summary", "details", "severity",
                  "fixed_version", "package", "status", "justification",
                  "impact_statement", "evidence"):
        assert field in first, field
    assert first["evidence"]["import"][0]["file"] == "app.py"


def test_real_artifact_files_written_and_named(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s2", "repo-a"),
        {}, settings=settings, runner=fake_runner(), repository_id="repo-a")
    out = Path(result["artifacts"]["report"]).parent

    assert result["artifact_names"] == {
        "report": "report.json", "sbom": "sbom.cdx.json",
        "vex": "openvex.json", "trace": "trace.json"}
    for key, filename in result["artifact_names"].items():
        assert (out / filename).is_file(), filename
        assert Path(result["artifacts"][key]).is_file()
    sbom = json.loads((out / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    vex = json.loads((out / "openvex.json").read_text(encoding="utf-8"))
    assert "openvex.dev" in vex["@context"]


def test_command_uses_out_dir_flag_not_output_dir(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s3", "repo-a"),
        {}, settings=settings, runner=fake_runner(), repository_id="repo-a")
    command = result["scan"]["command"]
    assert "--out-dir" in command
    assert "--output-dir" not in command
    assert "-m" in command and "chainguard_mvp.cli" in command
    assert "--no-llm" in command


def test_stdout_and_stderr_captured_and_persisted(settings, allowed_root) -> None:
    def runner(command, cwd, timeout):
        from chainguard_api.service import RunOutcome
        out_dir = Path(command[list(command).index("--out-dir") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "report.json").write_text(json.dumps(report_payload("x")),
                                             encoding="utf-8")
        return RunOutcome(0, stdout="all good\n", stderr="a warning\n", duration_ms=5)

    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s4", "repo-a"),
        {}, settings=settings, runner=runner, repository_id="repo-a")
    assert "all good" in result["scan"]["stdout"]
    assert "a warning" in result["scan"]["stderr"]
    out = Path(result["artifacts"]["report"]).parent
    assert (out / "stdout.log").read_text(encoding="utf-8") == "all good\n"
    assert (out / "stderr.log").read_text(encoding="utf-8") == "a warning\n"


def test_invalid_path_isolated_as_failed_result(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root.parent / "outside"), _out(settings, "s5", "bad"),
        {}, settings=settings, runner=fake_runner(), repository_id="bad")
    assert result["status"] == "failed"
    assert result["state"] == "INVALID_INPUT"
    assert result["error"]["code"] == "INVALID_REPOSITORY"
    assert result["vulnerabilities"] == []


def test_missing_engine_fails_clearly(fake_engine, allowed_root) -> None:
    settings = Settings(engine_root=fake_engine.parent / "nope",
                        allowed_root=allowed_root,
                        workspace_dir=allowed_root / "scan_workspace",
                        max_concurrent_scans=2, scan_timeout_seconds=5,
                        python_executable=sys.executable)
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s6", "repo-a"),
        {}, settings=settings, runner=fake_runner(), repository_id="repo-a")
    assert result["status"] == "failed"
    assert result["state"] == "ENGINE_ERROR"
    assert result["error"]["code"] == "ENGINE_UNAVAILABLE"


def test_exit_code_1_maps_to_actionable(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s7", "repo-a"),
        {"fail_on_actionable": True}, settings=settings,
        runner=fake_runner(exit_code=1), repository_id="repo-a")
    assert result["status"] == "completed"
    assert result["state"] == "ACTIONABLE"


def test_exit_code_2_maps_to_invalid_input(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s8", "repo-a"),
        {}, settings=settings,
        runner=fake_runner(exit_code=2, write_report=False), repository_id="repo-a")
    assert result["status"] == "failed"
    assert result["state"] == "INVALID_INPUT"
    assert result["error"]["code"] == "SCAN_INVALID_INPUT"


def test_unexpected_exit_code_maps_to_engine_error(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s9", "repo-a"),
        {}, settings=settings,
        runner=fake_runner(exit_code=9, write_report=False), repository_id="repo-a")
    assert result["status"] == "failed"
    assert result["state"] == "ENGINE_ERROR"
    assert result["error"]["code"] == "SCAN_FAILED"


def test_missing_report_is_not_silently_success(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "s10", "repo-a"),
        {}, settings=settings,
        runner=fake_runner(write_report=False), repository_id="repo-a")
    assert result["status"] == "failed"
    assert result["error"]["code"] == "OUTPUT_MISSING"


def test_timeout_is_reported_as_timeout(settings, allowed_root) -> None:
    result = scan_repository(
        str(allowed_root / "repo-b"), _out(settings, "s11", "repo-b"),
        {}, settings=settings, runner=fake_runner(timeout_error=True),
        repository_id="repo-b")
    assert result["status"] == "timeout"
    assert result["state"] == "TIMEOUT"
    assert result["error"]["code"] == "SCAN_TIMEOUT"


def test_default_runner_enforces_timeout(tmp_path: Path) -> None:
    """Controlled fake subprocess: a hanging engine is killed at the deadline."""
    outcome = default_runner(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        cwd=tmp_path, timeout=0.5)
    assert outcome.timed_out is True
    assert outcome.duration_ms < 5000
    assert "terminated" in (outcome.error or "")


def test_output_directories_never_collide(settings, allowed_root) -> None:
    first = scan_repository(
        str(allowed_root / "repo-a"), _out(settings, "iso", "repo-a"), {},
        settings=settings, runner=fake_runner(), repository_id="repo-a")
    second = scan_repository(
        str(allowed_root / "repo-b"), _out(settings, "iso", "repo-b"), {},
        settings=settings, runner=fake_runner(), repository_id="repo-b")
    assert first["artifacts"]["report"] != second["artifacts"]["report"]
    target_a = json.loads(Path(first["artifacts"]["report"]).read_text(encoding="utf-8"))["target"]
    target_b = json.loads(Path(second["artifacts"]["report"]).read_text(encoding="utf-8"))["target"]
    assert target_a != target_b            # no overwrite
    assert "repo-a" in target_a and "repo-b" in target_b


def test_fleet_aggregation_equals_sum_of_results(settings, allowed_root) -> None:
    results = [
        scan_repository(str(allowed_root / name), _out(settings, "agg", name), {},
                        settings=settings, runner=fake_runner(), repository_id=name)
        for name in ("repo-a", "repo-b", "repo-c")
    ]
    summary = aggregate_fleet(results)
    assert summary["total_repositories"] == 3
    assert summary["completed"] == 3
    assert summary["failed"] == 0
    assert summary["total_vulnerabilities"] == sum(
        r["summary"]["total_vulnerabilities"] for r in results) == 9
    assert summary["dismissed_unreachable"] == 6
    assert summary["actionable"] == 3
    assert summary["suspicious_packages"] == 3
    assert summary["noise_reduced_percent"] == 66.7
    # evidence is never merged across repositories
    assert len({r["artifacts"]["report"] for r in results}) == 3

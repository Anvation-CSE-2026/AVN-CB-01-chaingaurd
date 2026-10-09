"""Controlled tests with REAL child processes.

The other API tests use a runner double. These three use real ``subprocess``
children so the concurrency bound, the timeout kill and fleet isolation are
verified against the operating system, not against a mock:

  * peak concurrency <= MAX_CONCURRENT_SCANS (and genuinely parallel)
  * a hanging child is terminated when the timeout elapses (heartbeat stops)
  * one hanging repository does not cancel its fleet siblings
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from chainguard_api.app import create_app
from chainguard_api.config import Settings
from chainguard_api.schemas import FleetResponse
from chainguard_api.service import RunOutcome, default_runner
from conftest import Tracker, report_payload

HANGING_CHILD = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "beat = Path(sys.argv[1])\n"
    "counter = 0\n"
    "while True:\n"
    "    counter += 1\n"
    "    beat.write_text(str(counter))\n"
    "    time.sleep(0.05)\n"
)
SLEEP_CHILD = "import sys, time; time.sleep(float(sys.argv[1]))"


def _write_artifacts(command: list[str], repo: str) -> None:
    """Write the four artifacts the service adapter expects to find."""
    out_dir = Path(command[list(command).index("--out-dir") + 1])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report_payload(repo)), encoding="utf-8")
    (out_dir / "sbom.cdx.json").write_text(json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}), encoding="utf-8")
    (out_dir / "openvex.json").write_text(json.dumps(
        {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}), encoding="utf-8")
    (out_dir / "trace.json").write_text(json.dumps(
        {"schema_version": 1, "stages": []}), encoding="utf-8")


def _sleeping_runner(delay: float, tracker: Tracker):
    def runner(command, cwd, timeout):
        with tracker:
            started = time.perf_counter()
            subprocess.run([sys.executable, "-c", SLEEP_CHILD, str(delay)],
                           capture_output=True, text=True, timeout=timeout, check=False)
            _write_artifacts(list(command), str(command[3]))
            return RunOutcome(0, "ok\n", "", int((time.perf_counter() - started) * 1000))
    return runner


def test_peak_concurrency_of_real_subprocesses_is_bounded(settings, allowed_root) -> None:
    tracker = Tracker()
    repositories = [{"id": f"repo-{letter}", "path": str(allowed_root / f"repo-{letter}")}
                    for letter in "abcde"]
    with TestClient(create_app(settings=settings,
                               runner=_sleeping_runner(0.5, tracker))) as client:
        response = client.post("/scan/fleet", json={"repositories": repositories})

    fleet = FleetResponse.model_validate(response.json())
    assert fleet.summary.completed == 5, response.text
    assert tracker.calls == 5
    # A bounded pool must never exceed the configured limit, and with five
    # half-second children it must actually reach it (not serialize).
    assert tracker.peak == settings.max_concurrent_scans == 2


def test_timeout_terminates_the_real_child_process(tmp_path: Path) -> None:
    beat = tmp_path / "heartbeat.txt"
    started = time.perf_counter()
    outcome = default_runner([sys.executable, "-c", HANGING_CHILD, str(beat)],
                             tmp_path, 0.7)
    elapsed = time.perf_counter() - started

    assert outcome.timed_out is True
    assert outcome.returncode == -1
    assert elapsed < 5, "the timeout must fire instead of waiting for the child"
    assert beat.exists(), "the child really did run"

    # The child keeps writing while it is alive; after the timeout no further
    # write may appear, which proves the process was actually terminated.
    time.sleep(0.4)
    frozen = beat.read_text(encoding="utf-8")
    time.sleep(0.6)
    assert beat.read_text(encoding="utf-8") == frozen


def test_fleet_timeout_does_not_cancel_siblings_with_real_processes(fake_engine,
                                                                  allowed_root,
                                                                  tmp_path: Path) -> None:
    settings = Settings(engine_root=fake_engine, allowed_root=allowed_root,
                        workspace_dir=allowed_root / "scan_workspace",
                        max_concurrent_scans=2, scan_timeout_seconds=1,
                        python_executable=sys.executable, default_no_llm=True)

    def runner(command, cwd, timeout):
        repo = str(command[3])
        if repo.endswith("repo-b"):
            return default_runner([sys.executable, "-c", HANGING_CHILD,
                                   str(tmp_path / "beat-b.txt")], cwd, timeout)
        outcome = default_runner([sys.executable, "-c", "pass"], cwd, timeout)
        _write_artifacts(list(command), repo)
        return outcome

    with TestClient(create_app(settings=settings, runner=runner)) as client:
        response = client.post("/scan/fleet", json={"repositories": [
            {"id": "repo-a", "path": str(allowed_root / "repo-a")},
            {"id": "repo-b", "path": str(allowed_root / "repo-b")},
            {"id": "repo-c", "path": str(allowed_root / "repo-c")}]})

    assert response.status_code == 200, response.text
    fleet = FleetResponse.model_validate(response.json())
    assert fleet.status == "partial"
    assert [r.status for r in fleet.results] == ["completed", "timeout", "completed"]
    assert fleet.results[1].error.code == "SCAN_TIMEOUT"
    assert fleet.summary.completed == 2 and fleet.summary.failed == 1
    assert fleet.results[1].summary is None
    assert fleet.summary.total_vulnerabilities == sum(
        r.summary.total_vulnerabilities for r in fleet.results if r.summary)

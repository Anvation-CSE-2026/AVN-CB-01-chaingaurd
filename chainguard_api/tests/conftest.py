"""Shared fixtures: a test-double engine, controlled runners, settings."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from chainguard_api.config import Settings

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
REAL_ENGINE_ROOT = WORKSPACE_ROOT / "software supply chain mvp"
REAL_TEST_PROJECT = REAL_ENGINE_ROOT / "test_project"

ENGINE_MODULES = ("cli.py", "parsers.py", "osv.py", "reachability.py")

FAKE_CLI = '''"""Test-double engine entry point (unit tests only)."""
if __name__ == "__main__":
    print("usage: chainguard_mvp.cli (test double)")
'''


@pytest.fixture()
def fake_engine(tmp_path: Path) -> Path:
    """Minimal directory that satisfies the real-engine file verification."""
    pkg = tmp_path / "engine" / "chainguard_mvp"
    pkg.mkdir(parents=True)
    for name in ENGINE_MODULES:
        (pkg / name).write_text(FAKE_CLI if name == "cli.py" else "# test double\n",
                                encoding="utf-8")
    return tmp_path / "engine"


@pytest.fixture()
def allowed_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "repo-a").mkdir(parents=True)
    (root / "repo-b").mkdir(parents=True)
    (root / "repo-c").mkdir(parents=True)
    (root / "repo-d").mkdir(parents=True)
    (root / "repo-e").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    return root


@pytest.fixture()
def settings(fake_engine: Path, allowed_root: Path, tmp_path: Path) -> Settings:
    return Settings(
        engine_root=fake_engine,
        allowed_root=allowed_root,
        workspace_dir=allowed_root / "scan_workspace",
        max_concurrent_scans=2,
        scan_timeout_seconds=300,
        python_executable=sys.executable,
        default_no_llm=True,
    )


def report_payload(target: str, *, total=3, dismissed=2, actionable=1,
                   suspicious=1) -> dict:
    """Deterministic stand-in for report.json (unit tests only)."""
    return {
        "schema_version": 1,
        "target": target,
        "packages": [{"name": "example", "version": "1.0.0",
                      "ecosystem": "PyPI", "purl": "pkg:pypi/example@1.0.0"}],
        "vulnerabilities": [
            {"id": f"TEST-{index}", "aliases": [], "summary": "synthetic",
             "details": "synthetic", "severity": [], "fixed_version": None,
             "package": {"name": "example", "version": "1.0.0",
                         "ecosystem": "PyPI", "purl": "pkg:pypi/example@1.0.0"},
             "status": "not_affected" if index < dismissed else "affected",
             "justification": "vulnerable_code_not_in_execute_path",
             "impact_statement": "No calls found.",
             "evidence": {"vulnerable_functions": ["demo_fn"],
                          "import": [{"file": "app.py", "line": 1,
                                      "kind": "import", "name": "example"}],
                          "calls": []}}
            for index in range(total)
        ],
        "suspicious_packages": [{"package": {"name": "typo-example",
                                             "version": "0.0.1",
                                             "ecosystem": "PyPI",
                                             "purl": "pkg:pypi/typo-example@0.0.1"},
                                 "suspicious": True, "status": "SUSPICIOUS",
                                 "reasons": ["package not found in registry"]}]
        * suspicious if suspicious else [],
        "summary": {
            "total_vulnerabilities": total,
            "dismissed_unreachable": dismissed,
            "actionable": actionable,
            "suspicious_packages": suspicious,
            "noise_reduced_percent": round((dismissed / total) * 100, 1) if total else 0.0,
        },
    }


class Tracker:
    """Records peak concurrency across runner invocations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls = 0

    def __enter__(self) -> "Tracker":
        with self._lock:
            self.active += 1
            self.calls += 1
            self.peak = max(self.peak, self.active)
        return self

    def __exit__(self, *exc) -> None:
        with self._lock:
            self.active -= 1


def fake_runner(*, exit_code: int = 0, delay: float = 0.0,
                timeout_error: bool = False, tracker: Tracker | None = None,
                report=None, write_report: bool = True):
    """Controlled runner double that writes real artifacts like the scanner."""

    def runner(command, cwd: Path, timeout: float):
        started = time.perf_counter()
        if tracker is not None:
            with tracker:
                if delay:
                    time.sleep(delay)
                return _outcome(command, cwd, exit_code, started,
                                timeout_error=timeout_error, report=report,
                                write_report=write_report)
        if delay:
            time.sleep(delay)
        return _outcome(command, cwd, exit_code, started,
                        timeout_error=timeout_error, report=report,
                        write_report=write_report)

    return runner


def _outcome(command, cwd, exit_code, started, *, timeout_error, report, write_report):
    from chainguard_api.service import RunOutcome
    if timeout_error:
        raise subprocess.TimeoutExpired(cmd=list(command), timeout=300)
    out_dir = Path(command[list(command).index("--out-dir") + 1])
    repo = Path(command[3])
    if write_report:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = report if report is not None else report_payload(str(repo))
        (out_dir / "report.json").write_text(json.dumps(payload), encoding="utf-8")
        (out_dir / "sbom.cdx.json").write_text(
            json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5",
                        "components": []}), encoding="utf-8")
        (out_dir / "openvex.json").write_text(
            json.dumps({"@context": "https://openvex.dev/ns/v0.2.0",
                        "statements": []}), encoding="utf-8")
        (out_dir / "trace.json").write_text(
            json.dumps({"schema_version": 1, "stages": []}), encoding="utf-8")
    return RunOutcome(exit_code, stdout=f"scan of {repo}\n", stderr="",
                      duration_ms=int((time.perf_counter() - started) * 1000))

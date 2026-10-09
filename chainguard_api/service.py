"""Canonical single-repository scan adapter around the REAL ChainGuard CLI.

Responsibilities (Phase 3): validate the repository path, create an isolated
output directory, invoke ``python -m chainguard_mvp.cli --out-dir ...`` as an
argument array (never a shell string), capture stdout/stderr/exit code/runtime,
parse report.json / sbom.cdx.json / openvex.json / trace.json, keep the raw
artifact locations, and return one normalised repository result.

The scanner itself is never modified and its output is never rewritten beyond
truncating captured console text inside the API response (the full text is kept
in stdout.log / stderr.log next to the artifacts).
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .config import Settings, get_settings
from .engine import EngineStatus, build_command, verify_engine
from .paths import PathValidationError, validate_output_directory, validate_repository_path

ARTIFACT_FILES: dict[str, str] = {
    "report": "report.json",
    "sbom": "sbom.cdx.json",
    "vex": "openvex.json",
    "trace": "trace.json",
}

#: Exit-code semantics of the real scanner (Phase 10).
EXIT_COMPLETED = 0
EXIT_ACTIONABLE = 1          # only with --fail-on-actionable
EXIT_INVALID_INPUT = 2       # bad path / arguments / git reference


class RunOutcome:
    """Result of one engine invocation."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "",
                 duration_ms: int = 0, timed_out: bool = False,
                 error: str | None = None) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.timed_out = timed_out
        self.error = error


Runner = Callable[[Sequence[str], Path, float], RunOutcome]


def default_runner(command: Sequence[str], cwd: Path, timeout: float) -> RunOutcome:
    """Real subprocess execution: argument array, no shell, hard timeout."""
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            list(command), cwd=str(cwd), capture_output=True, text=True,
            timeout=timeout, check=False, shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return RunOutcome(
            returncode=-1,
            stdout=_decode(exc.stdout), stderr=_decode(exc.stderr),
            duration_ms=int((time.perf_counter() - started) * 1000),
            timed_out=True,
            error=f"engine exceeded {timeout:g}s and was terminated",
        )
    except OSError as exc:
        return RunOutcome(
            returncode=-1, duration_ms=int((time.perf_counter() - started) * 1000),
            error=f"could not execute engine: {exc}",
        )
    return RunOutcome(proc.returncode, proc.stdout or "", proc.stderr or "",
                      int((time.perf_counter() - started) * 1000))


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def failed_result(repository_id: str, repository_path: str, code: str, message: str,
                  state: str = "INVALID_INPUT", *, scan: dict[str, Any] | None = None,
                  artifacts: dict[str, Any] | None = None,
                  execution: dict[str, Any] | None = None) -> dict[str, Any]:
    """The one canonical failure shape (local or remote).

    Public so the remote executor can report a failure in exactly the same shape
    as a local engine failure: a caller must not have to learn two error formats,
    and a failed remote run must still disclose that it was remote.
    """
    return {
        "repository": {"id": repository_id, "path": repository_path},
        "status": "failed",
        "state": state,
        "scan": scan,
        "summary": None,
        "vulnerabilities": [],
        "suspicious_packages": [],
        "unresolved_dependencies": [],
        "artifacts": artifacts,
        "artifact_names": dict(ARTIFACT_FILES),
        "execution": execution,
        "error": {"code": code, "message": message},
    }


def scan_repository(
    repository_path: str | Path,
    output_directory: str | Path,
    options: Mapping[str, Any] | None = None,
    *,
    settings: Settings | None = None,
    runner: Runner | None = None,
    repository_id: str = "repository",
) -> dict[str, Any]:
    """Scan exactly one repository with the real engine (Phase 3 contract)."""
    settings = settings or get_settings()
    runner = runner or default_runner
    options = dict(options or {})
    raw_path = str(repository_path)
    raw_out = str(output_directory)

    # 1. repository path validation (traversal / symlink escape / existence)
    try:
        repo = validate_repository_path(repository_path, settings.allowed_root)
    except PathValidationError as exc:
        return failed_result(repository_id, raw_path, exc.code, str(exc), "INVALID_INPUT")

    # 2. isolated output directory, also confined to the allowed root
    try:
        out_dir = validate_output_directory(output_directory, settings.allowed_root)
    except PathValidationError as exc:
        return failed_result(repository_id, raw_path, exc.code, str(exc), "INVALID_INPUT")

    # 3. real engine must be present -- never a stub fallback
    engine: EngineStatus = verify_engine(settings.engine_root)
    if not engine.available:
        return failed_result(repository_id, raw_path, "ENGINE_UNAVAILABLE",
                       engine.detail or "real ChainGuard engine not found",
                       "ENGINE_ERROR")

    out_dir.mkdir(parents=True, exist_ok=True)

    # 4. build the real CLI command (argument array)
    command = build_command(
        settings.python_executable, repo, out_dir,
        no_llm=bool(options.get("no_llm", settings.default_no_llm)),
        fail_on_actionable=bool(options.get("fail_on_actionable", False)),
        dashboard=bool(options.get("dashboard", False)),
        diff_ref=options.get("diff_ref") or None,
    )

    # 5-8. run and capture stdout / stderr / exit code / duration
    try:
        outcome = runner(command, settings.engine_root,
                         float(settings.scan_timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        outcome = RunOutcome(
            -1, _decode(getattr(exc, "stdout", None)),
            _decode(getattr(exc, "stderr", None)), 0, timed_out=True,
            error=f"engine exceeded {settings.scan_timeout_seconds:g}s and was terminated")
    except OSError as exc:
        outcome = RunOutcome(-1, error=f"could not execute engine: {exc}")
    try:
        (out_dir / "stdout.log").write_text(outcome.stdout or "", encoding="utf-8")
        (out_dir / "stderr.log").write_text(outcome.stderr or "", encoding="utf-8")
    except OSError:
        pass

    scan_meta = {
        "exit_code": outcome.returncode,
        "duration_ms": outcome.duration_ms,
        "command": list(command),
        "stdout": (outcome.stdout or "")[: settings.max_stdout_chars],
        "stderr": (outcome.stderr or "")[: settings.max_stdout_chars],
    }
    artifact_paths = _artifact_paths(out_dir)
    artifacts = {**artifact_paths,
                 "stdout_log": str(out_dir / "stdout.log"),
                 "stderr_log": str(out_dir / "stderr.log")}

    if outcome.timed_out:
        return {
            **failed_result(repository_id, raw_path, "SCAN_TIMEOUT",
                      outcome.error or "scan timed out", "TIMEOUT",
                      scan=scan_meta, artifacts=artifacts),
            "status": "timeout",
        }
    if outcome.error:
        return failed_result(repository_id, raw_path, "ENGINE_EXECUTION_FAILED",
                       outcome.error, "ENGINE_ERROR",
                       scan=scan_meta, artifacts=artifacts)
    if outcome.returncode == EXIT_INVALID_INPUT:
        return failed_result(repository_id, raw_path, "SCAN_INVALID_INPUT",
                       "scanner rejected the target (exit code 2): "
                       + (outcome.stderr or outcome.stdout or "").strip()[:400],
                       "INVALID_INPUT", scan=scan_meta, artifacts=artifacts)
    if outcome.returncode not in (EXIT_COMPLETED, EXIT_ACTIONABLE):
        return failed_result(repository_id, raw_path, "SCAN_FAILED",
                       f"scanner exited with unexpected code {outcome.returncode}",
                       "ENGINE_ERROR", scan=scan_meta, artifacts=artifacts)

    # 9-12. parse the real artifacts
    report = _read_json(out_dir / ARTIFACT_FILES["report"])
    if report is None:
        return failed_result(repository_id, raw_path, "OUTPUT_MISSING",
                       "scanner finished but report.json is missing or unreadable",
                       "ENGINE_ERROR", scan=scan_meta, artifacts=artifacts)

    summary_raw = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    # Start from the scanner's own summary so numeric fields the adapter does
    # not model are still carried through (the schema allows extra fields).
    summary = dict(summary_raw)
    summary.update({
        "total_vulnerabilities": int(summary_raw.get("total_vulnerabilities", 0) or 0),
        "dismissed_unreachable": int(summary_raw.get("dismissed_unreachable", 0) or 0),
        "actionable": int(summary_raw.get("actionable", 0) or 0),
        "suspicious_packages": int(summary_raw.get("suspicious_packages", 0) or 0),
        "noise_reduced_percent": float(summary_raw.get("noise_reduced_percent", 0.0) or 0.0),
    })
    vulnerabilities = [v for v in report.get("vulnerabilities", []) if isinstance(v, dict)]
    suspicious = [p for p in report.get("suspicious_packages", []) if isinstance(p, dict)]
    unresolved = [d for d in report.get("unresolved_dependencies", []) if isinstance(d, dict)]

    return {
        "repository": {"id": repository_id, "path": str(repo)},
        "status": "completed",
        "state": "ACTIONABLE" if outcome.returncode == EXIT_ACTIONABLE else "COMPLETED",
        "scan": scan_meta,
        "summary": summary,
        "vulnerabilities": vulnerabilities,
        "suspicious_packages": suspicious,
        "unresolved_dependencies": unresolved,
        "artifacts": artifacts,
        "artifact_names": dict(ARTIFACT_FILES),
        "error": None,
    }


def _artifact_paths(out_dir: Path) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for key, filename in ARTIFACT_FILES.items():
        path = out_dir / filename
        found[key if key != "vex" else "vex"] = str(path) if path.is_file() else None
    dashboard = out_dir / "dashboard.html"
    found["dashboard"] = str(dashboard) if dashboard.is_file() else None
    return found


def aggregate_fleet(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Fleet totals = strict sum of repository results (never double-counted)."""
    completed = sum(1 for r in results if r.get("status") == "completed")
    failed = sum(1 for r in results if r.get("status") in {"failed", "timeout"})
    total = dismissed = actionable = suspicious = 0
    for result in results:
        summary = result.get("summary") or {}
        total += int(summary.get("total_vulnerabilities", 0) or 0)
        dismissed += int(summary.get("dismissed_unreachable", 0) or 0)
        actionable += int(summary.get("actionable", 0) or 0)
        suspicious += int(summary.get("suspicious_packages", 0) or 0)
    return {
        "total_repositories": len(results),
        "completed": completed,
        "failed": failed,
        "total_vulnerabilities": total,
        "dismissed_unreachable": dismissed,
        "actionable": actionable,
        "suspicious_packages": suspicious,
        "noise_reduced_percent": round((dismissed / total) * 100, 1) if total else 0.0,
    }

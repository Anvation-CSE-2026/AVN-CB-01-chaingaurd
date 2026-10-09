"""Discovery and verification of the REAL ChainGuard engine.

The API never falls back to a stub: either the configured directory contains
the real 11-module engine, or the service reports itself degraded and refuses
to scan.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

ENTRYPOINT = "chainguard_mvp.cli"
PACKAGE_DIR = "chainguard_mvp"

#: Files whose presence proves the configured directory holds the real engine.
REQUIRED_ENGINE_FILES = ("cli.py", "parsers.py", "osv.py", "reachability.py")


def _read_engine_version(root: Path) -> str | None:
    init_file = root / PACKAGE_DIR / "__init__.py"
    if not init_file.is_file():
        return None
    try:
        content = init_file.read_text(encoding="utf-8")
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None
    except OSError:
        return None


@dataclass(frozen=True)
class EngineStatus:
    available: bool
    implementation: str          # "real" | "missing"
    type: str                    # "real" | "missing"
    path: str | None
    entrypoint: str
    version: str | None = None
    missing: tuple[str, ...] = ()
    executable: bool | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "available": self.available,
            "version": self.version,
            "implementation": self.implementation,
            "type": self.type,
            "path": self.path,
            "entrypoint": self.entrypoint,
        }
        if self.missing:
            payload["missing"] = list(self.missing)
        if self.detail:
            payload["detail"] = self.detail
        return payload


def verify_engine(engine_root: Path) -> EngineStatus:
    """File-level verification (fast, no subprocess)."""
    root = Path(engine_root)
    if not root.is_dir():
        return EngineStatus(False, "missing", "missing", str(root), ENTRYPOINT,
                            version=None, missing=(f"{root} (directory)",),
                            detail="engine root directory does not exist")
    missing = tuple(f"{PACKAGE_DIR}/{name}" for name in REQUIRED_ENGINE_FILES
                    if not (root / PACKAGE_DIR / name).is_file())
    if missing:
        return EngineStatus(False, "missing", "missing", str(root), ENTRYPOINT,
                            version=None, missing=missing,
                            detail="real engine modules are not present in the configured directory")
    version = _read_engine_version(root)
    return EngineStatus(True, "real", "real", str(root), ENTRYPOINT, version=version)


def engine_executable(engine_root: Path, python: str, timeout: float = 20.0) -> tuple[bool, str]:
    """Prove the real engine can actually be executed and reach its data source.

    Two checks, both read-only:
      1. ``python -m chainguard_mvp.cli --help`` (entry point resolves)
      2. ``python -c "import requests"`` -- the engine's only declared runtime
         dependency. Without it the scanner silently reports ZERO vulnerabilities
         (OSV lookups degrade to empty results), which would make the API report
         an empty-but-successful scan. That failure mode must be loud.
    """
    try:
        proc = subprocess.run(
            [python, "-m", ENTRYPOINT, "--help"],
            cwd=str(engine_root), capture_output=True, text=True,
            timeout=timeout, check=False, shell=False,
        )
    except FileNotFoundError:
        return False, f"interpreter not found: {python}"
    except subprocess.TimeoutExpired:
        return False, f"engine did not answer --help within {timeout}s"
    except OSError as error:
        return False, f"could not execute engine: {error}"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-300:]
        return False, f"engine --help exited {proc.returncode}: {tail}"
    try:
        dep = subprocess.run(
            [python, "-c", "import requests"], capture_output=True, text=True,
            timeout=timeout, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, f"could not verify engine dependencies: {error}"
    if dep.returncode != 0:
        return False, ("engine dependency 'requests' is missing from the interpreter "
                       f"used to run the engine ({python}); OSV lookups would silently "
                       "return no vulnerabilities")
    return True, "engine executed successfully"


def health_payload(engine_root: Path, python: str, timeout: float = 20.0) -> dict[str, Any]:
    status = verify_engine(engine_root)
    if not status.available:
        return {"status": "degraded", "engine": status.as_dict()}
    executable, detail = engine_executable(engine_root, python, timeout=timeout)
    payload = status.as_dict()
    payload["executable"] = executable
    if not executable:
        payload["detail"] = detail
    return {
        "status": "ok" if executable else "degraded",
        "engine": {**payload, "available": bool(executable),
                   "implementation": "real" if executable else "missing"},
    }


def build_command(python: str, repository: Path, output_directory: Path,
                  *, no_llm: bool = True, fail_on_actionable: bool = False,
                  dashboard: bool = False, diff_ref: str | None = None) -> list[str]:
    """Argument array for the real scanner (never a shell string)."""
    command: list[str] = [python, "-m", ENTRYPOINT, str(repository),
                          "--out-dir", str(output_directory)]
    if no_llm:
        command.append("--no-llm")
    if fail_on_actionable:
        command.append("--fail-on-actionable")
    if dashboard:
        command.append("--dashboard")
    if diff_ref:
        command.extend(["--diff", diff_ref])
    return command

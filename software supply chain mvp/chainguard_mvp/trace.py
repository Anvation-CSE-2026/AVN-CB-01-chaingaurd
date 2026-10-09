"""Structured trace collection for a ChainGuard scan."""
from __future__ import annotations

import json
import math
import time
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


class _Stage(AbstractContextManager["_Stage"]):
    def __init__(self, tracer: "Tracer", name: str, items_in: int = 0) -> None:
        self.tracer = tracer
        self.name = name
        self.started_at = ""
        self._started = 0.0
        self.items_in = items_in
        self.items_out = 0
        self.summary: dict[str, Any] = {}
        self.items: list[Any] = []

    def __enter__(self) -> "_Stage":
        self.started_at = _timestamp()
        self._started = time.perf_counter()
        return self

    def record(self, *, items_in: int | None = None, items_out: int | None = None,
               summary: dict[str, Any] | None = None, items: list[Any] | None = None) -> None:
        if items_in is not None:
            self.items_in = items_in
        if items_out is not None:
            self.items_out = items_out
        if summary is not None:
            self.summary = summary
        if items is not None:
            self.items = items

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        elapsed = (time.perf_counter() - self._started) * 1000
        record = {
            "stage": self.name,
            "started_at": self.started_at,
            "duration_ms": round(elapsed, 3),
            "items_in": self.items_in,
            "items_out": self.items_out,
            "summary": self.summary,
            "items": self.items,
        }
        if exc_type is not None:
            record["summary"]["error"] = str(exc_value)
        self.tracer.stages.append(_jsonable(record))
        return False


class Tracer:
    """Accumulates per-stage, per-package, and per-advisory scan evidence."""

    def __init__(self, run_metadata: dict[str, Any] | None = None) -> None:
        self.stages: list[dict[str, Any]] = []
        self.journeys: dict[str, dict[str, Any]] = {}
        self.evidence_chains: list[dict[str, Any]] = []
        self.totals: dict[str, Any] = {}
        self.run_metadata = run_metadata or {}

    def stage(self, name: str, items_in: int = 0) -> _Stage:
        return _Stage(self, name, items_in)

    def register_package(self, package: dict[str, Any]) -> None:
        purl = str(package.get("purl", "n/a"))
        if purl not in self.journeys:
            self.journeys[purl] = {"package": package.get("name", "n/a"), "purl": purl, "events": []}

    def journey_event(self, package: dict[str, Any], stage: str, result: str,
                      detail: Any = "n/a", evidence: list[str] | None = None) -> None:
        self.register_package(package)
        event: dict[str, Any] = {"stage": stage, "result": result, "detail": _jsonable(detail)}
        if evidence:
            event["evidence"] = evidence
        self.journeys[package["purl"]]["events"].append(event)

    def add_evidence_chain(self, chain: dict[str, Any]) -> None:
        self.evidence_chains.append(_jsonable(chain))

    def as_dict(self) -> dict[str, Any]:
        return _jsonable({
            "schema_version": 1,
            "stages": self.stages,
            "journeys": list(self.journeys.values()),
            "evidence_chains": self.evidence_chains,
            "totals": self.totals,
            "run_metadata": self.run_metadata,
        })

    def write(self, path: str | Path) -> dict[str, Any]:
        data = self.as_dict()
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return data

"""OpenVEX 0.2.0 serialization."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def build_vex(decisions: list[dict[str, Any]], author: str = "chainguard_mvp") -> dict[str, Any]:
    statements = []
    for decision in decisions:
        status = decision.get("status", "affected")
        statement: dict[str, Any] = {
            "vulnerability": {"name": decision["id"]},
            "products": [{"@id": decision["package"]["purl"]}],
            "status": status,
            "impact_statement": decision.get("impact_statement", "Reachability assessment is best effort."),
        }
        if status == "not_affected":
            statement["justification"] = decision.get("justification", "component_not_present")
        statements.append(statement)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:uuid:{__import__('uuid').uuid4()}",
            "author": author, "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "version": 1, "statements": statements}


def write_vex(decisions: list[dict[str, Any]], path: str | Path, author: str = "chainguard_mvp") -> dict[str, Any]:
    data = build_vex(decisions, author)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data

"""CycloneDX SBOM generation with a dependency-free fallback."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Security Policy: Unpinned `npx -y @cyclonedx/cdxgen` executes `@latest` without version pinning.
# We pin a compatible release explicitly (`@cyclonedx/cdxgen@10.9.0`) to avoid unpinned dynamic npm execution.
PINNED_CDXGEN_PACKAGE = "@cyclonedx/cdxgen@10.9.0"


def _fallback(packages: list[dict[str, str]]) -> dict[str, Any]:
    components = []
    dependencies = []
    for package in packages:
        component = {"type": "library", "bom-ref": package["purl"], "name": package["name"],
                    "version": package["version"], "purl": package["purl"]}
        if package["ecosystem"] == "PyPI":
            component["purl"] = package["purl"]
        components.append(component)
        dependencies.append({"ref": package["purl"], "dependsOn": []})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                     "tools": [{"vendor": "chainguard_mvp", "name": "chainguard_mvp", "version": "0.1.0"}]},
        "components": components, "dependencies": dependencies,
    }


def create_sbom(root: str | Path, packages: list[dict[str, str]], out_file: str | Path) -> dict[str, Any]:
    root, out_file = Path(root).resolve(), Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if os.getenv("CHAINGUARD_DISABLE_CDXGEN", "").lower() in {"1", "true", "yes"}:
        data = _fallback(packages)
        out_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return data
    npx, node = shutil.which("npx"), shutil.which("node")
    if npx and node:
        cdxgen_pkg = os.getenv("CHAINGUARD_CDXGEN_PACKAGE", PINNED_CDXGEN_PACKAGE)
        try:
            result = subprocess.run([npx, "-y", cdxgen_pkg, "-o", str(out_file.resolve()), str(root)],
                                    capture_output=True, text=True, timeout=120, check=False)
            if result.returncode == 0 and out_file.is_file():
                parsed = json.loads(out_file.read_text(encoding="utf-8"))
                if parsed.get("bomFormat") == "CycloneDX" and parsed.get("specVersion") == "1.5":
                    return parsed
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            pass
    data = _fallback(packages)
    out_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data

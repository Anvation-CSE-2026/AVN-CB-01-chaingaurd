"""Read-only artifact serving for the dashboard.

This is an *additive* API surface: it exposes the four artifacts the scanner
already writes for a scan (``report.json``, ``trace.json``, ``sbom.cdx.json``,
``openvex.json``) so the browser can view or download exactly what is on disk.

Safety rules (this module accepts untrusted identifiers, never a path):

* the scan id must be 32 lowercase hex characters (the shape the API creates);
* the repository id is validated with the same rules that create output
  directories (:func:`chainguard_api.paths.validate_repository_id`);
* the artifact name must be in :data:`ARTIFACT_NAMES` — an allowlist, so a
  request can never name ``../../.env`` or ``stdout.log``;
* the resolved file is required to stay inside the configured scan workspace
  (symlinks resolved), and a missing file is a 404 rather than a crash.

Nothing here can create, modify or delete a scan: it is a read path only.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from .config import Settings
from .paths import PathValidationError, validate_repository_id, is_within_root

#: Artifacts the dashboard may read. Order is the display order.
ARTIFACT_NAMES: tuple[str, ...] = ("report.json", "trace.json", "sbom.cdx.json",
                                   "openvex.json")

#: Every exposed artifact is JSON (CycloneDX and OpenVEX are JSON encodings).
ARTIFACT_MEDIA_TYPE = "application/json"

SCAN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def _bad(code: str, message: str) -> HTTPException:
    return HTTPException(status_code=400, detail={"code": code, "message": message})


def _not_found(code: str, message: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"code": code, "message": message})


def create_artifacts_router(settings: Settings) -> APIRouter:
    """Build the artifact router bound to ``settings`` (workspace location)."""
    router = APIRouter(tags=["artifacts"])

    @router.get("/scans/{scan_id}/repositories/{repository_id}/artifacts/{name}",
                summary="View or download one scanner artifact")
    def artifact(scan_id: str, repository_id: str, name: str,
                 download: bool = Query(False, description="force a download")):
        if not SCAN_ID_PATTERN.match(scan_id):
            raise _bad("INVALID_SCAN_ID",
                       "scan id must be the 32-character hexadecimal id the API returned")
        try:
            safe_repo = validate_repository_id(repository_id)
        except PathValidationError as error:
            raise _bad("INVALID_REPOSITORY_ID", str(error)) from error
        if name not in ARTIFACT_NAMES:
            raise _bad("INVALID_ARTIFACT_NAME",
                       "artifact must be one of: " + ", ".join(ARTIFACT_NAMES))

        workspace = Path(settings.workspace_dir)
        candidate = workspace / scan_id / safe_repo / name
        if not is_within_root(candidate, workspace):
            raise _not_found("ARTIFACT_NOT_FOUND",
                             "no artifact at that location inside the scan workspace")
        resolved = candidate.resolve()
        if not resolved.is_file():
            raise _not_found("ARTIFACT_NOT_FOUND",
                             f"{name} was not produced for this repository")
        return FileResponse(
            resolved,
            media_type=ARTIFACT_MEDIA_TYPE,
            filename=name if download else None,
        )

    return router

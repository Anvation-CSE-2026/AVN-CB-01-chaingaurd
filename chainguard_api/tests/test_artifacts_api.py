"""Artifact serving: the dashboard's read-only view of real scanner output.

These tests pin the security properties of the new surface:

* only the four scanner artifacts can ever be named (allowlist);
* the scan id must have the exact shape the API creates;
* the repository id goes through the same validator that creates directories;
* a file outside the scan workspace is never served (symlink escape included);
* a missing artifact is a 404, never a crash or an invented file.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chainguard_api.app import create_app
from chainguard_api.artifacts import ARTIFACT_NAMES

SCAN_ID = "a" * 32
REPO_ID = "repo-a"

ARTIFACT_BODIES = {
    "report.json": {"schema_version": 1, "packages": [], "vulnerabilities": [],
                    "suspicious_packages": [],
                    "summary": {"total_vulnerabilities": 0}},
    "trace.json": {"schema_version": 1, "stages": []},
    "sbom.cdx.json": {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []},
    "openvex.json": {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []},
}


@pytest.fixture()
def scan_workspace(settings) -> Path:
    """A workspace containing one scan with all four real artifact names."""
    out_dir = Path(settings.workspace_dir) / SCAN_ID / REPO_ID
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, body in ARTIFACT_BODIES.items():
        (out_dir / name).write_text(json.dumps(body), encoding="utf-8")
    # Files the dashboard must never be able to read, next to real artifacts.
    (out_dir / "stdout.log").write_text("console output\n", encoding="utf-8")
    (Path(settings.workspace_dir) / "secret.txt").write_text("not an artifact\n",
                                                             encoding="utf-8")
    return Path(settings.workspace_dir)


def url(scan_id: str = SCAN_ID, repo_id: str = REPO_ID,
        name: str = "report.json") -> str:
    return f"/scans/{scan_id}/repositories/{repo_id}/artifacts/{name}"


# ------------------------------------------------------------------ happy path

@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_each_real_artifact_is_viewable(settings, scan_workspace, name: str) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(url(name=name))

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert json.loads(response.content) == ARTIFACT_BODIES[name]
    # Inline view: no forced download.
    assert "attachment" not in response.headers.get("content-disposition", "")


def test_download_flag_forces_attachment(settings, scan_workspace) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(url(name="sbom.cdx.json") + "?download=true")

    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "sbom.cdx.json" in response.headers["content-disposition"]


def test_scan_id_is_reported_for_artifact_links(settings) -> None:
    """A client can only build artifact URLs if the response carries the id."""
    from chainguard_api.schemas import RepositoryResult

    result = RepositoryResult.model_validate({
        "repository": {"id": REPO_ID, "path": str(settings.allowed_root / REPO_ID)},
        "scan_id": SCAN_ID, "status": "completed", "state": "COMPLETED",
    })
    assert result.scan_id == SCAN_ID


# --------------------------------------------------------------- rejection

@pytest.mark.parametrize("name", ["stdout.log", "stderr.log", "dashboard.html",
                                  "report.txt", "..%2F..%2Fsecret.txt", "x"])
def test_unknown_artifact_names_are_never_served(settings, scan_workspace,
                                                name: str) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(url(name=name))

    # Either the router does not match the path (encoded separators) or the
    # allowlist rejects it; in both cases nothing is served.
    assert response.status_code in {400, 404}
    if response.status_code == 400:
        assert response.json()["detail"]["code"] == "INVALID_ARTIFACT_NAME"


@pytest.mark.parametrize("scan_id", ["../../etc", "..", "A" * 32, "a" * 31, "a" * 33,
                                     "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "0" * 31 + "!"])
def test_malformed_scan_ids_are_rejected(settings, scan_workspace, scan_id: str) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(url(scan_id=scan_id))

    assert response.status_code in {400, 404}
    if response.status_code == 400:
        assert response.json()["detail"]["code"] == "INVALID_SCAN_ID"


@pytest.mark.parametrize("repo_id", ["..", "../evil", "a/b", "a\\b", "", "with space",
                                     "-leading"])
def test_unsafe_repository_ids_are_rejected(settings, scan_workspace,
                                            repo_id: str) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(url(repo_id=repo_id))

    assert response.status_code in {400, 404}
    if response.status_code == 400:
        assert response.json()["detail"]["code"] == "INVALID_REPOSITORY_ID"


def test_valid_but_unknown_scan_id_is_not_found(settings, scan_workspace) -> None:
    with TestClient(create_app(settings)) as client:
        response = client.get(url(scan_id="b" * 32))

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "ARTIFACT_NOT_FOUND"


def test_missing_artifact_in_a_known_scan_is_not_found(settings, scan_workspace) -> None:
    empty_repo = Path(settings.workspace_dir) / SCAN_ID / "repo-b"
    empty_repo.mkdir(parents=True, exist_ok=True)

    with TestClient(create_app(settings)) as client:
        response = client.get(url(repo_id="repo-b"))

    assert response.status_code == 404


def test_symlink_escape_is_not_served(settings, scan_workspace) -> None:
    """A link inside the scan workspace that points outside must not be served."""
    outside = Path(settings.workspace_dir).parent / "outside-artifacts"
    outside.mkdir(exist_ok=True)
    (outside / "report.json").write_text('{"escaped": true}', encoding="utf-8")
    link = Path(settings.workspace_dir) / SCAN_ID / "repo-link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError) as error:  # pragma: no cover - host dependent
        pytest.skip(f"symlinks unavailable on this host: {error}")

    with TestClient(create_app(settings)) as client:
        response = client.get(url(repo_id="repo-link"))

    assert response.status_code == 404
    assert b"escaped" not in response.content

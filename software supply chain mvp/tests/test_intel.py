"""Tests for the persistent intelligence store.

All archives and advisories here are SYNTHETIC test fixtures built inside pytest
temporary directories. They use obviously fictional package names and are never
written to the user's production store, which holds only genuinely imported
OpenSSF records.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from chainguard_mvp import intel, osv
from chainguard_mvp.intel import (
    IntelError,
    IntelStore,
    match_malicious,
    parse_malicious_archive,
    refresh_malicious,
    source_status,
)

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
ALL_VERSIONS = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
BOUNDED = [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}]


def _zip(entries: dict[str, object]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in entries.items():
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
            archive.writestr(name, data)
    return buffer.getvalue()


def _record(record_id: str, ecosystem: str, name: str, versions=None, ranges=None, withdrawn=None) -> dict:
    record = {"id": record_id, "summary": f"Synthetic fixture record for {name}",
              "affected": [{"package": {"ecosystem": ecosystem, "name": name},
                            "versions": list(versions or []), "ranges": list(ranges or [])}]}
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


def _package(name: str, version: str, ecosystem: str = "PyPI") -> dict[str, str]:
    purl_type = {"PyPI": "pypi", "npm": "npm", "Maven": "maven", "crates.io": "cargo"}[ecosystem]
    return {"name": name, "version": version, "ecosystem": ecosystem,
            "purl": f"pkg:{purl_type}/{name}@{version}"}


@pytest.fixture()
def fixture_archive(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic-malicious.zip"
    path.write_bytes(_zip({
        "repo-main/osv/malicious/PyPI/chainguard-fixture-exact/MAL-T-0001.json":
            _record("MAL-T-0001", "PyPI", "chainguard-fixture-exact", versions=["1.0.0"]),
        "repo-main/osv/malicious/PyPI/chainguard-fixture-all/MAL-T-0002.json":
            _record("MAL-T-0002", "PyPI", "chainguard-fixture-all", ranges=ALL_VERSIONS),
        "repo-main/osv/malicious/PyPI/chainguard-fixture-range/MAL-T-0003.json":
            _record("MAL-T-0003", "PyPI", "chainguard-fixture-range", ranges=BOUNDED),
        "repo-main/osv/malicious/npm/chainguard-fixture-npm/MAL-T-0004.json":
            _record("MAL-T-0004", "npm", "chainguard-fixture-npm", versions=["2.0.0"]),
    }))
    return path


@pytest.fixture()
def store(tmp_path: Path) -> IntelStore:
    handle = IntelStore(tmp_path / "intel.sqlite")
    yield handle
    handle.close()


# ------------------------------------------------------------ archive parsing

def test_parse_reads_nested_layout_merges_duplicates_and_counts_skips() -> None:
    archive = _zip({
        "repo-main/osv/malicious/PyPI/chainguard-fixture-alpha/MAL-T-1.json":
            _record("MAL-T-1", "PyPI", "chainguard-fixture-alpha", versions=["1.0.0"]),
        "repo-main/osv/malicious/PyPI/chainguard-fixture-alpha/MAL-T-1-copy.json":
            _record("MAL-T-1", "PyPI", "chainguard-fixture-alpha", versions=["2.0.0"]),
        "repo-main/osv/malicious/crates.io/chainguard-fixture-cargo/MAL-T-2.json":
            _record("MAL-T-2", "crates.io", "chainguard-fixture-cargo", versions=["0.1.0"]),
        "repo-main/osv/malicious/PyPI/chainguard-fixture-w/MAL-T-3.json":
            _record("MAL-T-3", "PyPI", "chainguard-fixture-w", withdrawn="2025-01-01T00:00:00Z"),
        "repo-main/osv/malicious/PyPI/chainguard-fixture-bad/MAL-T-4.json": b"{not json",
    })
    rows, skipped = parse_malicious_archive(archive)
    assert [(r["record_id"], r["name"]) for r in rows] == [("MAL-T-1", "chainguard-fixture-alpha")]
    assert sorted(rows[0]["versions"]) == ["1.0.0", "2.0.0"]
    assert skipped == {"withdrawn": 1, "unsupported_ecosystem": 1, "invalid_record": 1, "no_package": 0}


def test_parse_rejects_invalid_or_empty_archives() -> None:
    with pytest.raises(IntelError) as bad_zip:
        parse_malicious_archive(b"this is not a zip archive")
    assert bad_zip.value.kind == "invalid_archive"
    with pytest.raises(IntelError) as empty:
        parse_malicious_archive(_zip({"repo-main/README.md": "no records here"}))
    assert empty.value.kind == "invalid_archive"


# ------------------------------------------------------------------ matching

def test_match_modes_are_distinct_and_normalised(store: IntelStore, fixture_archive: Path) -> None:
    result = refresh_malicious(store, from_zip=fixture_archive, now=NOW)
    assert result["status"] == "ok"
    assert result["records_imported"] == 4

    exact = match_malicious(store, _package("chainguard-fixture-exact", "1.0.0"))
    assert [m["match"] for m in exact] == ["exact_version"]
    assert match_malicious(store, _package("chainguard-fixture-exact", "9.9.9")) == []

    everything = match_malicious(store, _package("chainguard-fixture-all", "4.2.0"))
    assert [m["match"] for m in everything] == ["all_versions"]

    candidate = match_malicious(store, _package("chainguard-fixture-range", "1.1.0"))
    assert [m["match"] for m in candidate] == ["candidate_range_unevaluated"]

    # PEP 503 normalisation: underscores and case must not hide a match.
    assert match_malicious(store, _package("Chainguard_Fixture_Exact", "1.0.0"))

    # Ecosystems are not crossed: the npm record does not match a PyPI package of the same name.
    assert match_malicious(store, _package("chainguard-fixture-npm", "2.0.0", "PyPI")) == []
    assert match_malicious(store, _package("chainguard-fixture-npm", "2.0.0", "npm"))[0]["match"] == "exact_version"

    # Unsupported ecosystems are never matched.
    assert match_malicious(store, _package("chainguard-fixture-exact", "1.0.0", "crates.io")) == []


# ------------------------------------------------------- failure behaviour

def test_failed_refresh_keeps_previous_records_and_reports_failure(
        store: IntelStore, fixture_archive: Path, tmp_path: Path) -> None:
    assert refresh_malicious(store, from_zip=fixture_archive, now=NOW)["status"] == "ok"
    failed = refresh_malicious(store, from_zip=tmp_path / "missing.zip", now=NOW + timedelta(days=1))
    assert failed["status"] == "failed"
    assert failed["error_kind"] == "read_error"
    assert match_malicious(store, _package("chainguard-fixture-exact", "1.0.0"))
    row = store.source(intel.MALICIOUS_SOURCE)
    assert row["last_status"] == "failed"
    assert row["last_success_at"] == "2026-10-09T12:00:00Z"
    assert source_status(row, NOW + timedelta(days=1)) == "failed_using_stale_records"


def test_download_timeout_is_reported_as_timeout(store: IntelStore) -> None:
    with patch.object(intel.requests, "get", side_effect=requests.Timeout("synthetic timeout")):
        result = refresh_malicious(store, timeout=1.0, now=NOW)
    assert result["status"] == "failed"
    assert result["error_kind"] == "timeout"
    assert store.source(intel.MALICIOUS_SOURCE)["last_status"] == "failed"


def test_failed_replace_rolls_back_the_whole_source(store: IntelStore, fixture_archive: Path) -> None:
    refresh_malicious(store, from_zip=fixture_archive, now=NOW)
    before = len(store.malicious_for("PyPI", "chainguard-fixture-exact"))
    broken = [{"record_id": "MAL-T-9", "ecosystem": "PyPI", "name": "x", "name_norm": "x",
               "versions": set(), "ranges": [], "summary": "", "aliases": [], "published": None,
               "modified": None, "source_path": "p", "record_sha256": "h"},
              {"record_id": "MAL-T-10"}]  # missing keys -> KeyError mid-write
    with pytest.raises(KeyError):
        store.replace_malicious(intel.MALICIOUS_SOURCE, "file:x", broken, content_sha256="h",
                                skipped={}, attempted=NOW, imported=NOW)
    assert len(store.malicious_for("PyPI", "chainguard-fixture-exact")) == before


def test_source_status_never_loaded_and_stale(store: IntelStore, fixture_archive: Path) -> None:
    assert source_status(store.source(intel.MALICIOUS_SOURCE), NOW) == "never_loaded"
    refresh_malicious(store, from_zip=fixture_archive, now=NOW)
    row = store.source(intel.MALICIOUS_SOURCE)
    assert source_status(row, NOW) == "fresh"
    assert source_status(row, NOW + timedelta(days=8)) == "stale"


# ------------------------------------------------------------- OSV lookups

def _osv_fake(advisories: dict[str, dict], batch_results: list[list[str]]):
    """Build a fake ``osv._request`` that answers querybatch and vulns lookups."""
    def fake(method, url, timeout, **kwargs):
        if url.endswith("/querybatch"):
            return {"results": [{"vulns": [{"id": vid} for vid in ids]} for ids in batch_results]}, None
        vuln_id = url.rsplit("/", 1)[-1]
        return advisories[vuln_id], None
    return fake


def test_osv_live_advisory_and_malicious_split(store: IntelStore) -> None:
    package = _package("chainguard-fixture-osv", "1.0.0")
    advisories = {
        "SYNTH-ADV-1": {"id": "SYNTH-ADV-1", "summary": "synthetic advisory", "affected": [],
                        "aliases": ["SYNTH-CVE-1"]},
        "MAL-SYNTH-1": {"id": "MAL-SYNTH-1", "summary": "synthetic malicious record", "affected": []},
    }
    with patch.object(osv, "_request", side_effect=_osv_fake(advisories, [["SYNTH-ADV-1", "MAL-SYNTH-1"]])):
        result = osv.query_osv([package], store=store, timeout=1.0, now=NOW)
    assert result["lookups"][0]["status"] == "live"
    assert [v["id"] for v in result["vulnerabilities"]] == ["SYNTH-ADV-1"]
    assert [m["record_id"] for m in result["malicious"]] == ["MAL-SYNTH-1"]
    assert result["malicious"][0]["source"] == "osv.dev"
    assert result["malicious"][0]["match"] == "osv_version_matched"


def test_osv_cache_within_ttl_makes_no_request(store: IntelStore) -> None:
    package = _package("chainguard-fixture-osv", "1.0.0")
    advisories = {"SYNTH-ADV-1": {"id": "SYNTH-ADV-1", "summary": "s", "affected": []}}
    with patch.object(osv, "_request", side_effect=_osv_fake(advisories, [["SYNTH-ADV-1"]])):
        osv.query_osv([package], store=store, timeout=1.0, now=NOW)
    with patch.object(osv, "_request", side_effect=AssertionError("cache must answer")) as network:
        cached = osv.query_osv([package], store=store, timeout=1.0, now=NOW + timedelta(hours=1))
    network.assert_not_called()
    assert cached["lookups"][0]["status"] == "cached"
    assert [v["id"] for v in cached["vulnerabilities"]] == ["SYNTH-ADV-1"]


def test_osv_failure_uses_stale_cache_and_says_so(store: IntelStore) -> None:
    package = _package("chainguard-fixture-osv", "1.0.0")
    advisories = {"SYNTH-ADV-1": {"id": "SYNTH-ADV-1", "summary": "s", "affected": []}}
    with patch.object(osv, "_request", side_effect=_osv_fake(advisories, [["SYNTH-ADV-1"]])):
        osv.query_osv([package], store=store, timeout=1.0, now=NOW)
    later = NOW + timedelta(days=2)
    with patch.object(osv, "_request", return_value=(None, "timeout")):
        result = osv.query_osv([package], store=store, timeout=1.0, now=later)
    row = result["lookups"][0]
    assert row["status"] == "stale_cache"
    assert row["error"] == "timeout"
    assert [v["id"] for v in result["vulnerabilities"]] == ["SYNTH-ADV-1"]


def test_osv_failure_without_cache_is_unavailable_not_clean(store: IntelStore) -> None:
    package = _package("chainguard-fixture-osv", "1.0.0")
    with patch.object(osv, "_request", return_value=(None, "http_503")):
        result = osv.query_osv([package], store=store, timeout=1.0, now=NOW)
    row = result["lookups"][0]
    assert row["status"] == "unavailable"
    assert row["error"] == "http_503"
    assert result["vulnerabilities"] == []


def test_unsupported_ecosystem_is_never_queried(store: IntelStore) -> None:
    with patch.object(osv, "_request", side_effect=AssertionError("must not query")) as network:
        result = osv.query_osv([_package("chainguard-fixture-cargo", "0.1.0", "crates.io")],
                               store=store, timeout=1.0, now=NOW)
    network.assert_not_called()
    assert result["lookups"][0]["status"] == "unsupported_ecosystem"


def test_osv_without_store_still_reports_status() -> None:
    package = _package("chainguard-fixture-osv", "1.0.0")
    with patch.object(osv, "_request", return_value=(None, "timeout")):
        result = osv.query_osv([package], store=None, timeout=1.0, now=NOW)
    assert result["lookups"][0]["status"] == "unavailable"
    assert result["lookups"][0]["error"] == "timeout"

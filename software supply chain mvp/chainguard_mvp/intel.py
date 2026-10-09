"""Persistent security-intelligence store.

Two sources stay separate in storage and in reporting:

* ``osv.dev`` -- known vulnerabilities (OSV advisories) and OSV ``MAL-*``
  malicious-package records, cached here with fetch timestamps.
* ``openssf-malicious-packages`` -- the OpenSSF Malicious Packages dataset,
  imported from its GitHub archive or a local copy of that archive.

Neither source feeds the reachability verdict. Name-similarity signals stay in
``slopsquat.py``. Every failure is recorded in the ``sources`` table with its
reason; a failed refresh keeps the previously imported records.

CLI::

    python -m chainguard_mvp.intel refresh [--db PATH] [--timeout S]
                                          [--from-zip ARCHIVE] [--skip-osv]
    python -m chainguard_mvp.intel status [--db PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import requests
except ImportError:  # downloads and live OSV lookups report an explicit error without it
    requests = None

SCHEMA_VERSION = 1
MALICIOUS_SOURCE = "openssf-malicious-packages"
MALICIOUS_ARCHIVE_URL = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.zip"
OSV_SOURCE = "osv.dev"
#: ecosystems the parsers emit and the store can match; anything else is reported as unsupported.
SUPPORTED_ECOSYSTEMS = ("PyPI", "npm", "Maven")
OSV_QUERY_TTL = timedelta(hours=24)
OSV_DETAIL_TTL = timedelta(days=7)
MALICIOUS_STALE_AFTER = timedelta(days=7)
DEFAULT_TIMEOUT = 30.0
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_RECORD_BYTES = 5 * 1024 * 1024

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    last_attempt_at TEXT,
    last_success_at TEXT,
    last_status TEXT,
    last_error TEXT,
    record_count INTEGER NOT NULL DEFAULT 0,
    content_sha256 TEXT,
    skipped_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS malicious_records (
    source TEXT NOT NULL,
    record_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    name_norm TEXT NOT NULL,
    versions_json TEXT NOT NULL,
    ranges_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    aliases_json TEXT NOT NULL,
    published TEXT,
    modified TEXT,
    source_path TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    PRIMARY KEY (source, record_id, ecosystem, name_norm)
);
CREATE INDEX IF NOT EXISTS malicious_lookup ON malicious_records (ecosystem, name_norm);
CREATE TABLE IF NOT EXISTS osv_queries (
    ecosystem TEXT NOT NULL,
    name_norm TEXT NOT NULL,
    version TEXT NOT NULL,
    name TEXT NOT NULL,
    purl TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    vulnerability_ids_json TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name_norm, version)
);
CREATE TABLE IF NOT EXISTS osv_vulnerabilities (
    id TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
"""


class IntelError(Exception):
    """A source update failed; ``kind`` is a short machine-readable reason."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def default_db_path() -> Path:
    override = os.environ.get("CHAINGUARD_INTEL_DB")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "chainguard" / "intel.sqlite"


def normalize_name(ecosystem: str, name: str) -> str:
    value = name.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", value).lower()
    return value.lower()


def purl_base(purl: str) -> str:
    return purl.rsplit("@", 1)[0]


def is_all_versions(ranges: list[dict[str, Any]]) -> bool:
    """True when a range introduces at 0 and never fixes or ends, i.e. every version is affected."""
    for item in ranges:
        events = item.get("events", []) if isinstance(item, dict) else []
        introduced = [e.get("introduced") for e in events if isinstance(e, dict) and "introduced" in e]
        bounded = any(isinstance(e, dict) and ("fixed" in e or "last_affected" in e or "limit" in e)
                      for e in events)
        if "0" in introduced and not bounded:
            return True
    return False


class IntelStore:
    """SQLite-backed store. Writes happen inside transactions; WAL lets scans read during refresh."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 10000")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "IntelStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------- sources
    def source(self, name: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM sources WHERE name = ?", (name,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["skipped"] = json.loads(data.pop("skipped_json") or "{}")
        return data

    def record_failure(self, name: str, url: str, kind: str, message: str, attempted: datetime) -> None:
        """Mark an update failed. Previously imported records are kept."""
        with self.conn:
            self.conn.execute(
                """INSERT INTO sources (name, url, last_attempt_at, last_status, last_error)
                   VALUES (?, ?, ?, 'failed', ?)
                   ON CONFLICT(name) DO UPDATE SET url = excluded.url,
                       last_attempt_at = excluded.last_attempt_at,
                       last_status = 'failed', last_error = excluded.last_error""",
                (name, url, iso(attempted), f"{kind}: {message}"))

    def replace_malicious(self, name: str, url: str, rows: list[dict[str, Any]], *,
                          content_sha256: str, skipped: dict[str, int], attempted: datetime,
                          imported: datetime) -> None:
        """Replace one source's records atomically: all rows land, or none do."""
        with self.conn:
            self.conn.execute("DELETE FROM malicious_records WHERE source = ?", (name,))
            self.conn.executemany(
                """INSERT INTO malicious_records (source, record_id, ecosystem, name, name_norm,
                       versions_json, ranges_json, summary, aliases_json, published, modified,
                       source_path, record_sha256, imported_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(name, r["record_id"], r["ecosystem"], r["name"], r["name_norm"],
                  json.dumps(sorted(r["versions"])), json.dumps(r["ranges"]), r["summary"],
                  json.dumps(r["aliases"]), r["published"], r["modified"], r["source_path"],
                  r["record_sha256"], iso(imported)) for r in rows])
            self.conn.execute(
                """INSERT INTO sources (name, url, last_attempt_at, last_success_at, last_status,
                       last_error, record_count, content_sha256, skipped_json)
                   VALUES (?, ?, ?, ?, 'ok', NULL, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET url = excluded.url,
                       last_attempt_at = excluded.last_attempt_at,
                       last_success_at = excluded.last_success_at, last_status = 'ok',
                       last_error = NULL, record_count = excluded.record_count,
                       content_sha256 = excluded.content_sha256, skipped_json = excluded.skipped_json""",
                (name, url, iso(attempted), iso(imported),
                 len({r["record_id"] for r in rows}), content_sha256, json.dumps(skipped, sort_keys=True)))

    def malicious_for(self, ecosystem: str, name_norm: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT * FROM malicious_records WHERE ecosystem = ? AND name_norm = ?
               ORDER BY source, record_id""", (ecosystem, name_norm)).fetchall()
        results = []
        for row in rows:
            data = dict(row)
            data["versions"] = json.loads(data.pop("versions_json"))
            data["ranges"] = json.loads(data.pop("ranges_json"))
            data["aliases"] = json.loads(data.pop("aliases_json"))
            results.append(data)
        return results

    # ----------------------------------------------------------------- OSV
    def osv_query(self, ecosystem: str, name_norm: str, version: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM osv_queries WHERE ecosystem = ? AND name_norm = ? AND version = ?",
            (ecosystem, name_norm, version)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["vulnerability_ids"] = json.loads(data.pop("vulnerability_ids_json"))
        return data

    def put_osv_query(self, ecosystem: str, name_norm: str, version: str, name: str, purl: str,
                      fetched: datetime, vulnerability_ids: list[str]) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO osv_queries (ecosystem, name_norm, version, name, purl, fetched_at,
                       vulnerability_ids_json) VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ecosystem, name_norm, version) DO UPDATE SET name = excluded.name,
                       purl = excluded.purl, fetched_at = excluded.fetched_at,
                       vulnerability_ids_json = excluded.vulnerability_ids_json""",
                (ecosystem, name_norm, version, name, purl, iso(fetched), json.dumps(vulnerability_ids)))

    def all_osv_queries(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM osv_queries ORDER BY ecosystem, name_norm, version").fetchall()
        return [dict(row) for row in rows]

    def osv_vulnerability(self, vuln_id: str) -> tuple[dict[str, Any], datetime] | None:
        row = self.conn.execute("SELECT * FROM osv_vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row["payload_json"]), parse_time(row["fetched_at"])

    def put_osv_vulnerability(self, vuln_id: str, payload: dict[str, Any], fetched: datetime) -> None:
        with self.conn:
            self.conn.execute(
                """INSERT INTO osv_vulnerabilities (id, fetched_at, payload_json) VALUES (?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET fetched_at = excluded.fetched_at,
                       payload_json = excluded.payload_json""",
                (vuln_id, iso(fetched), json.dumps(payload, sort_keys=True)))


# ------------------------------------------------------- OpenSSF import

def _download(url: str, timeout: float) -> bytes:
    if requests is None:
        raise IntelError("client_unavailable", "requests is not installed")
    try:
        response = requests.get(url, timeout=timeout, stream=True,
                                headers={"User-Agent": "ChainGuard-Intel/1.0"})
    except requests.Timeout as exc:
        raise IntelError("timeout", f"download exceeded {timeout}s: {exc}") from exc
    except requests.RequestException as exc:
        raise IntelError("network_error", str(exc)) from exc
    with response:
        if response.status_code != 200:
            raise IntelError(f"http_{response.status_code}", f"GET {url} returned {response.status_code}")
        buffer = io.BytesIO()
        try:
            for chunk in response.iter_content(chunk_size=1 << 16):
                buffer.write(chunk)
                if buffer.tell() > MAX_ARCHIVE_BYTES:
                    raise IntelError("too_large", f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        except requests.Timeout as exc:
            raise IntelError("timeout", f"download stalled: {exc}") from exc
        except requests.RequestException as exc:
            raise IntelError("network_error", str(exc)) from exc
    return buffer.getvalue()


def parse_malicious_archive(data: bytes) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Parse OpenSSF malicious-package OSV records from a repository archive.

    Records with the same (id, ecosystem, normalized name) are merged, so one
    dataset record that lists a package twice yields one row. Withdrawn records
    and unsupported ecosystems are counted, never imported.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IntelError("invalid_archive", f"not a valid zip archive: {exc}") from exc
    skipped = {"withdrawn": 0, "unsupported_ecosystem": 0, "invalid_record": 0, "no_package": 0}
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    record_files = 0
    # Layout: <root>/osv/malicious/<ecosystem>/<package>/<MAL-id>.json (package directories are nested).
    member_pattern = re.compile(r"/osv/malicious/([^/]+)/.+\.json$")
    for info in archive.infolist():
        if info.is_dir() or not member_pattern.search(info.filename):
            continue
        record_files += 1
        if info.file_size > MAX_RECORD_BYTES:
            skipped["invalid_record"] += 1
            continue
        raw = archive.read(info)
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            skipped["invalid_record"] += 1
            continue
        record_id = record.get("id") if isinstance(record, dict) else None
        if not isinstance(record_id, str) or not record_id:
            skipped["invalid_record"] += 1
            continue
        if record.get("withdrawn"):
            skipped["withdrawn"] += 1
            continue
        affected = record.get("affected") or []
        if not isinstance(affected, list):
            skipped["invalid_record"] += 1
            continue
        digest = hashlib.sha256(raw).hexdigest()
        found_package = False
        for entry in affected:
            package = entry.get("package") if isinstance(entry, dict) else None
            if not isinstance(package, dict) or not package.get("name") or not package.get("ecosystem"):
                continue
            found_package = True
            ecosystem = str(package["ecosystem"])
            if ecosystem not in SUPPORTED_ECOSYSTEMS:
                skipped["unsupported_ecosystem"] += 1
                continue
            name = str(package["name"])
            key = (record_id, ecosystem, normalize_name(ecosystem, name))
            row = merged.setdefault(key, {
                "record_id": record_id, "ecosystem": ecosystem, "name": name, "name_norm": key[2],
                "versions": set(), "ranges": [], "summary": str(record.get("summary") or ""),
                "aliases": sorted({str(a) for a in record.get("aliases", []) if a}),
                "published": record.get("published"), "modified": record.get("modified"),
                "source_path": info.filename, "record_sha256": digest,
            })
            row["versions"].update(str(v) for v in entry.get("versions", []) if v)
            row["ranges"].extend(r for r in entry.get("ranges", []) if isinstance(r, dict))
        if not found_package:
            skipped["no_package"] += 1
    if record_files == 0:
        raise IntelError("invalid_archive", "archive contains no osv/malicious/<ecosystem>/*.json records")
    rows = sorted(merged.values(), key=lambda r: (r["ecosystem"], r["name_norm"], r["record_id"]))
    return rows, skipped


def refresh_malicious(store: IntelStore, *, timeout: float = DEFAULT_TIMEOUT,
                      from_zip: str | Path | None = None, now: datetime | None = None) -> dict[str, Any]:
    """Download (or read) the OpenSSF archive and replace its records atomically."""
    attempted = now or utc_now()
    if from_zip is not None:
        url = f"file:{Path(from_zip).resolve()}"
    else:
        url = MALICIOUS_ARCHIVE_URL
    try:
        data = Path(from_zip).read_bytes() if from_zip is not None else _download(url, timeout)
        rows, skipped = parse_malicious_archive(data)
    except IntelError as error:
        store.record_failure(MALICIOUS_SOURCE, url, error.kind, str(error), attempted)
        return {"source": MALICIOUS_SOURCE, "status": "failed", "error_kind": error.kind,
                "error": str(error), "url": url}
    except OSError as error:
        store.record_failure(MALICIOUS_SOURCE, url, "read_error", str(error), attempted)
        return {"source": MALICIOUS_SOURCE, "status": "failed", "error_kind": "read_error",
                "error": str(error), "url": url}
    content_sha256 = hashlib.sha256(data).hexdigest()
    store.replace_malicious(MALICIOUS_SOURCE, url, rows, content_sha256=content_sha256,
                            skipped=skipped, attempted=attempted, imported=attempted)
    return {"source": MALICIOUS_SOURCE, "status": "ok", "url": url,
            "records_imported": len({r["record_id"] for r in rows}), "package_rows": len(rows),
            "skipped": skipped, "content_sha256": content_sha256}


# ------------------------------------------------------------- matching

def match_malicious(store: IntelStore, package: dict[str, str]) -> list[dict[str, Any]]:
    """Return known-malicious matches for one package, with the strength of each match.

    ``exact_version`` and ``all_versions`` are confirmed by the record.
    ``candidate_range_unevaluated`` means the record names a version range this
    tool does not evaluate; it is reported as a candidate, never as confirmed.
    """
    ecosystem = package["ecosystem"]
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        return []
    matches = []
    for row in store.malicious_for(ecosystem, normalize_name(ecosystem, package["name"])):
        if is_all_versions(row["ranges"]):
            mode = "all_versions"
        elif package["version"] in row["versions"]:
            mode = "exact_version"
        elif row["ranges"]:
            mode = "candidate_range_unevaluated"
        else:
            continue
        matches.append({"record_id": row["record_id"], "source": row["source"], "match": mode,
                        "summary": row["summary"], "aliases": row["aliases"],
                        "reference": f"https://osv.dev/vulnerability/{row['record_id']}",
                        "package": package})
    return matches


def source_status(row: dict[str, Any] | None, now: datetime) -> str:
    if row is None or not row.get("last_success_at"):
        return "never_loaded" if row is None or row.get("last_status") != "failed" else "failed"
    if row.get("last_status") == "failed":
        return "failed_using_stale_records"
    age = now - parse_time(row["last_success_at"])
    return "stale" if age > MALICIOUS_STALE_AFTER else "fresh"


# ----------------------------------------------------------------- CLI

def _refresh_osv(store: IntelStore, timeout: float, now: datetime) -> dict[str, Any]:
    from .osv import refresh_stale_queries
    return refresh_stale_queries(store, timeout=timeout, now=now)


def _status(store: IntelStore, now: datetime) -> dict[str, Any]:
    row = store.source(MALICIOUS_SOURCE)
    malicious = {"name": MALICIOUS_SOURCE, "url": row["url"] if row else MALICIOUS_ARCHIVE_URL,
                 "status": source_status(row, now), "last_attempt_at": row and row["last_attempt_at"],
                 "last_success_at": row and row["last_success_at"], "last_error": row and row["last_error"],
                 "records": row["record_count"] if row else 0, "content_sha256": row and row["content_sha256"],
                 "skipped": row["skipped"] if row else {}}
    return {"db_path": str(store.path), "schema_version": SCHEMA_VERSION, "sources": [malicious],
            "osv_cached_queries": len(store.all_osv_queries())}


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chainguard_mvp.intel",
                                     description="Refresh and inspect the ChainGuard intelligence store")
    sub = parser.add_subparsers(dest="command", required=True)
    refresh = sub.add_parser("refresh", help="import OpenSSF malicious packages and re-query stale OSV entries")
    refresh.add_argument("--db", type=Path, default=None, help="SQLite path (default: CHAINGUARD_INTEL_DB or ~/.cache/chainguard/intel.sqlite)")
    refresh.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request timeout in seconds")
    refresh.add_argument("--from-zip", type=Path, default=None, help="import a local copy of the OpenSSF archive instead of downloading")
    refresh.add_argument("--skip-osv", action="store_true", help="do not re-query stale OSV cache entries")
    status = sub.add_parser("status", help="show source freshness and record counts")
    status.add_argument("--db", type=Path, default=None)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if getattr(args, "timeout", 1.0) <= 0:
        parser.error("--timeout must be greater than zero")

    db_path = args.db or default_db_path()
    now = utc_now()
    with IntelStore(db_path) as store:
        if args.command == "status":
            print(json.dumps(_status(store, now), indent=2))
            return 0
        results = {"malicious": refresh_malicious(store, timeout=args.timeout, from_zip=args.from_zip, now=now)}
        if not args.skip_osv:
            results["osv"] = _refresh_osv(store, args.timeout, now)
        print(json.dumps({"db_path": str(db_path), "results": results}, indent=2))
        failed = [name for name, item in results.items() if item.get("status") == "failed"]
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

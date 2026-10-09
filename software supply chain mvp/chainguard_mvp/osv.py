"""OSV.dev client with a persistent SQLite cache and explicit lookup status.

Every package gets one lookup status so a failed or stale lookup is never
mistaken for "no advisories":

* ``live``                -- queried from api.osv.dev during this scan
* ``cached``              -- answered from the store within its TTL
* ``stale_cache``         -- live query failed; the older cached answer is used
* ``unavailable``         -- live query failed and nothing is cached
* ``unsupported_ecosystem`` -- not queried

OSV ``MAL-*`` records describe malicious packages, not vulnerabilities. They
are returned separately under ``malicious`` and never receive a reachability
verdict.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from .intel import (
    DEFAULT_TIMEOUT,
    OSV_DETAIL_TTL,
    OSV_QUERY_TTL,
    OSV_SOURCE,
    SUPPORTED_ECOSYSTEMS,
    IntelStore,
    normalize_name,
    purl_base,
    utc_now,
)

try:
    import requests
except ImportError:  # live lookups report client_unavailable without the optional runtime
    requests = None

OSV_BASE = "https://api.osv.dev/v1"
MAX_BATCH_QUERIES = 1000  # querybatch limit
DETAIL_WORKERS = 8


def _request(method: str, url: str, timeout: float, **kwargs: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Return ``(payload, None)`` on success or ``(None, error_kind)`` on failure."""
    if requests is None:
        return None, "client_unavailable"
    error_kind = "network_error"
    for attempt in range(3):
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
            if response.status_code == 429 or response.status_code >= 500:
                error_kind = f"http_{response.status_code}"
                if attempt < 2:
                    time.sleep(0.25 * (2 ** attempt))
                    continue
                return None, error_kind
            if response.status_code >= 400:
                return None, f"http_{response.status_code}"
            value = response.json()
            if not isinstance(value, dict):
                return None, "invalid_response"
            return value, None
        except requests.Timeout:
            error_kind = "timeout"
        except requests.RequestException:
            error_kind = "network_error"
        except ValueError:
            return None, "invalid_response"
        if attempt < 2:
            time.sleep(0.25 * (2 ** attempt))
    return None, error_kind


def _fixed_version(vuln: dict[str, Any], purl: str) -> str | None:
    for affected in vuln.get("affected", []):
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        affected_purl = package.get("purl", "")
        if isinstance(affected_purl, str) and affected_purl:
            affected_base = affected_purl.rsplit("@", 1)[0]
            purl_base_value = purl.rsplit("@", 1)[0]
            if affected_base != purl_base_value:
                continue
        elif package.get("name"):
            expected = purl.rsplit("@", 1)[0].split("/")[-1].lower()
            if str(package["name"]).lower() != expected:
                continue
        for item in affected.get("ranges", []):
            for event in item.get("events", []):
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
        versions = affected.get("versions", [])
        if versions:
            return "see advisory"
    return None


def _severity(vuln: dict[str, Any]) -> list[dict[str, str]]:
    values = []
    for item in vuln.get("severity", []):
        if isinstance(item, dict):
            values.append({"type": str(item.get("type", "")), "score": str(item.get("score", ""))})
    return values


def _package_key(package: dict[str, str]) -> tuple[str, str, str]:
    return package["ecosystem"], normalize_name(package["ecosystem"], package["name"]), package["version"]


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[offset:offset + size] for offset in range(0, len(items), size)]


def _fetch_details(ids: list[str], store: IntelStore | None, timeout: float, now: datetime,
                   errors: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Return advisory payloads by id. Failed fetches fall back to cache or are recorded in ``errors``."""
    payloads: dict[str, dict[str, Any]] = {}
    to_fetch: list[str] = []
    for vuln_id in ids:
        cached = store.osv_vulnerability(vuln_id) if store else None
        if cached and now - cached[1] < OSV_DETAIL_TTL:
            payloads[vuln_id] = cached[0]
        else:
            to_fetch.append(vuln_id)
    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as executor:
        futures = {executor.submit(_request, "GET", f"{OSV_BASE}/vulns/{vuln_id}", timeout): vuln_id
                   for vuln_id in to_fetch}
        for future in as_completed(futures):
            vuln_id = futures[future]
            payload, error = future.result()
            if payload is not None:
                payloads[vuln_id] = payload
                if store:
                    store.put_osv_vulnerability(vuln_id, payload, now)
                continue
            cached = store.osv_vulnerability(vuln_id) if store else None
            if cached:
                payloads[vuln_id] = cached[0]
                errors[vuln_id] = f"{error}; using cached advisory from {cached[1].isoformat()}"
            else:
                errors[vuln_id] = str(error)
    return payloads


def _advisory_record(vuln: dict[str, Any], vuln_id: str, package: dict[str, str]) -> dict[str, Any]:
    aliases = sorted({str(a) for a in vuln.get("aliases", [])})
    summary = str(vuln.get("summary", ""))
    details = str(vuln.get("details", ""))
    return {
        "id": vuln_id,
        "aliases": aliases,
        "summary": summary,
        "details": details,
        "severity": _severity(vuln),
        "fixed_version": _fixed_version(vuln, package["purl"]),
        "package": package,
        "advisory_text": "\n".join(x for x in (summary, details) if x),
    }


def query_osv(packages: list[dict[str, str]], store: IntelStore | None = None,
              timeout: float = DEFAULT_TIMEOUT, now: datetime | None = None) -> dict[str, Any]:
    """Look up advisories and malicious records for packages.

    Returns ``vulnerabilities`` (advisories, one per package/advisory pair),
    ``malicious`` (OSV MAL-* records), ``lookups`` (one status per package) and
    ``detail_errors`` (advisory ids that could not be fetched).
    """
    now = now or utc_now()
    lookups: dict[tuple[str, str, str], dict[str, Any]] = {}
    ids_by_key: dict[tuple[str, str, str], list[str]] = {}
    pending: dict[tuple[str, str, str], dict[str, str]] = {}
    for package in packages:
        key = _package_key(package)
        if key in lookups:
            continue
        if package["ecosystem"] not in SUPPORTED_ECOSYSTEMS:
            lookups[key] = {"status": "unsupported_ecosystem", "fetched_at": None, "error": None,
                            "vulnerability_ids": []}
            continue
        cached = store.osv_query(*key) if store else None
        if cached and now - _parse(cached["fetched_at"]) < OSV_QUERY_TTL:
            lookups[key] = {"status": "cached", "fetched_at": cached["fetched_at"], "error": None,
                            "vulnerability_ids": cached["vulnerability_ids"]}
            ids_by_key[key] = cached["vulnerability_ids"]
        else:
            pending[key] = package

    if pending:
        keys = list(pending)
        for chunk in _chunks(keys, MAX_BATCH_QUERIES):
            batch = [{"package": {"purl": purl_base(pending[k]["purl"])}, "version": pending[k]["version"]}
                     for k in chunk]
            payload, error = _request("POST", f"{OSV_BASE}/querybatch", timeout, json={"queries": batch})
            results = payload.get("results") if payload else None
            if payload is not None and (not isinstance(results, list) or len(results) != len(chunk)):
                payload, error = None, "invalid_response"
            if payload is None:
                for key in chunk:
                    cached = store.osv_query(*key) if store else None
                    if cached:
                        lookups[key] = {"status": "stale_cache", "fetched_at": cached["fetched_at"],
                                        "error": error, "vulnerability_ids": cached["vulnerability_ids"]}
                        ids_by_key[key] = cached["vulnerability_ids"]
                    else:
                        lookups[key] = {"status": "unavailable", "fetched_at": None, "error": error,
                                        "vulnerability_ids": []}
                continue
            for key, result in zip(chunk, results):
                ids = [str(v["id"]) for v in (result.get("vulns") or []) if isinstance(v, dict) and v.get("id")]
                ids_by_key[key] = ids
                lookups[key] = {"status": "live", "fetched_at": now.isoformat().replace("+00:00", "Z"),
                                "error": None, "vulnerability_ids": ids}
                if store:
                    package = pending[key]
                    store.put_osv_query(key[0], key[1], key[2], package["name"], package["purl"], now, ids)

    all_ids = sorted({vid for ids in ids_by_key.values() for vid in ids})
    detail_errors: dict[str, str] = {}
    payloads = _fetch_details(all_ids, store, timeout, now, detail_errors)

    vulnerabilities: list[dict[str, Any]] = []
    malicious: list[dict[str, Any]] = []
    seen_malicious: set[tuple[str, str, str]] = set()
    lookup_rows = []
    for package in packages:
        key = _package_key(package)
        status = lookups[key]
        found = []
        for vuln_id in ids_by_key.get(key, []):
            if vuln_id in detail_errors and vuln_id not in payloads:
                continue
            vuln = payloads.get(vuln_id)
            if vuln is None:
                continue
            if vuln_id.startswith("MAL-"):
                if (vuln_id, key[0], key[1]) not in seen_malicious:
                    seen_malicious.add((vuln_id, key[0], key[1]))
                    malicious.append({
                        "record_id": vuln_id, "source": OSV_SOURCE,
                        "match": "osv_version_matched", "summary": str(vuln.get("summary", "")),
                        "aliases": sorted({str(a) for a in vuln.get("aliases", [])}),
                        "reference": f"https://osv.dev/vulnerability/{vuln_id}", "package": package,
                    })
                found.append(vuln_id)
                continue
            vulnerabilities.append(_advisory_record(vuln, vuln_id, package))
            found.append(vuln_id)
        lookup_rows.append({"package": package, "status": status["status"], "fetched_at": status["fetched_at"],
                            "error": status["error"], "vulnerability_ids": found,
                            "detail_errors": {vid: detail_errors[vid] for vid in ids_by_key.get(key, [])
                                              if vid in detail_errors}})
    return {"vulnerabilities": vulnerabilities, "malicious": malicious, "lookups": lookup_rows,
            "detail_errors": detail_errors}


def query_vulnerabilities(packages: list[dict[str, str]], store: IntelStore | None = None,
                          timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """Advisories only. Use :func:`query_osv` to also obtain status and malicious records."""
    return query_osv(packages, store=store, timeout=timeout)["vulnerabilities"]


def refresh_stale_queries(store: IntelStore, *, timeout: float = DEFAULT_TIMEOUT,
                          now: datetime | None = None) -> dict[str, Any]:
    """Re-query every cached OSV package/version whose entry is older than the query TTL."""
    now = now or utc_now()
    stale = []
    for row in store.all_osv_queries():
        if now - _parse(row["fetched_at"]) >= OSV_QUERY_TTL:
            stale.append({"name": row["name"], "ecosystem": row["ecosystem"], "version": row["version"],
                          "purl": row["purl"]})
    if not stale:
        return {"source": OSV_SOURCE, "status": "ok", "stale_entries": 0, "refreshed": 0, "failed": 0}
    result = query_osv(stale, store=store, timeout=timeout, now=now)
    failed = [row for row in result["lookups"] if row["status"] in ("stale_cache", "unavailable")]
    status = "failed" if failed and len(failed) == len(stale) else "ok"
    return {"source": OSV_SOURCE, "status": status, "stale_entries": len(stale),
            "refreshed": sum(row["status"] == "live" for row in result["lookups"]), "failed": len(failed),
            "failures": [{"package": row["package"]["name"], "version": row["package"]["version"],
                          "error": row["error"]} for row in failed][:20]}


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

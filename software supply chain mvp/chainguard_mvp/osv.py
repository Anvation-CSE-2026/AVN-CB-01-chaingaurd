"""OSV vulnerability database client."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

try:
    import requests
except ImportError:  # registry lookups become empty results without this optional runtime
    requests = None

OSV_BASE = "https://api.osv.dev/v1"


def _request_json(method: str, url: str, **kwargs: Any) -> dict[str, Any] | None:
    if requests is None:
        return None
    kwargs.setdefault("timeout", 20)
    for attempt in range(3):
        try:
            response = requests.request(method, url, **kwargs)
            if response.status_code >= 500 or response.status_code == 429:
                if attempt < 2:
                    time.sleep(0.25 * (2 ** attempt))
                    continue
            response.raise_for_status()
            value = response.json()
            return value if isinstance(value, dict) else None
        except (requests.RequestException, ValueError):
            if attempt < 2:
                time.sleep(0.25 * (2 ** attempt))
    return None


def _fixed_version(vuln: dict[str, Any], purl: str) -> str | None:
    for affected in vuln.get("affected", []):
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        affected_purl = package.get("purl", "")
        if isinstance(affected_purl, str) and affected_purl:
            affected_base = affected_purl.rsplit("@", 1)[0]
            purl_base = purl.rsplit("@", 1)[0]
            if affected_base != purl_base:
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


def query_vulnerabilities(packages: list[dict[str, str]]) -> list[dict[str, Any]]:
    if not packages:
        return []
    # OSV expects the version separately when a PURL is supplied; a versioned
    # PURL plus the explicit version is rejected as ambiguous by querybatch.
    batch = [{"package": {"purl": package["purl"].rsplit("@", 1)[0]}, "version": package["version"]}
             for package in packages]
    payload = _request_json("POST", f"{OSV_BASE}/querybatch", json={"queries": batch})
    if not payload:
        return []
    indexed: dict[str, list[dict[str, Any]]] = {}
    for package, result in zip(packages, payload.get("results", [])):
        if isinstance(result, dict):
            indexed[package["purl"]] = result.get("vulns", [])

    ids = sorted({str(v.get("id")) for vulns in indexed.values() for v in vulns
                  if isinstance(v, dict) and v.get("id")})
    cache: dict[str, dict[str, Any] | None] = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_request_json, "GET", f"{OSV_BASE}/vulns/{vuln_id}"): vuln_id
                   for vuln_id in ids}
        for future in as_completed(futures):
            cache[futures[future]] = future.result()

    results: list[dict[str, Any]] = []
    by_purl = {p["purl"]: p for p in packages}
    for purl, references in indexed.items():
        package = by_purl[purl]
        for reference in references:
            vuln_id = str(reference.get("id", ""))
            vuln = cache.get(vuln_id)
            if not vuln:
                continue
            aliases = sorted({str(a) for a in vuln.get("aliases", [])})
            summary = str(vuln.get("summary", ""))
            details = str(vuln.get("details", ""))
            results.append({
                "id": vuln_id,
                "aliases": aliases,
                "summary": summary,
                "details": details,
                "severity": _severity(vuln),
                "fixed_version": _fixed_version(vuln, purl),
                "package": package,
                "advisory_text": "\n".join(x for x in (summary, details) if x),
            })
    return results

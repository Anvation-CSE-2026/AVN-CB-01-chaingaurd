#!/usr/bin/env python3
"""Validate a CycloneDX SBOM against the live OSV vulnerability API.

This is an external validation utility for ChainGuard. It does not modify the
ChainGuard engine, infer code reachability, or declare unmatched packages safe.
Uses only Python's standard library.

Example:
  python chainguard_osv_validator.py --sbom path/to/sbom.cdx.json
  python chainguard_osv_validator.py --sbom sbom.cdx.json --out osv_validation.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
USER_AGENT = "ChainGuard-OSV-Validation/1.0"

# OSV ecosystem labels for common CycloneDX/PURL types.
PURL_TO_OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
    "apk": "Alpine",
    "deb": "Debian",
    "rpm": "Rocky Linux",
}


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """Return (purl_type, decoded_name, version), or None when unsupported."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "@" not in body:
        return None
    path, version = body.rsplit("@", 1)
    if "/" not in path or not version:
        return None
    purl_type, raw_name = path.split("/", 1)
    purl_type = purl_type.lower()
    raw_name = urllib.parse.unquote(raw_name)
    version = urllib.parse.unquote(version)
    if not raw_name or not version:
        return None

    # OSV identifies Maven packages with group:artifact and Go packages by
    # their full import path. PURL namespace paths encode these as slashes.
    if purl_type == "maven":
        parts = raw_name.split("/")
        name = ":".join(parts[-2:]) if len(parts) >= 2 else raw_name
    elif purl_type == "golang":
        name = raw_name
    else:
        name = raw_name
    return purl_type, name, version


def extract_queries(sbom: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    components = sbom.get("components", [])
    if not isinstance(components, list):
        raise ValueError("SBOM field 'components' must be a JSON array")

    queries: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for comp in components:
        if not isinstance(comp, dict):
            continue
        purl = comp.get("purl")
        parsed = parse_purl(purl) if purl else None
        label = str(comp.get("name") or purl or "(unnamed component)")
        if not parsed:
            skipped.append({
                "name": label,
                "purl": purl,
                "reason": "Missing or unsupported versioned purl",
            })
            continue
        purl_type, package_name, version = parsed
        ecosystem = PURL_TO_OSV_ECOSYSTEM.get(purl_type)
        if not ecosystem:
            skipped.append({
                "name": label,
                "purl": purl,
                "reason": f"Unsupported PURL type: {purl_type}",
            })
            continue
        identity = (ecosystem, package_name, version)
        if identity in seen:
            continue
        seen.add(identity)
        queries.append({
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
            "_component": {
                "name": comp.get("name"),
                "group": comp.get("group"),
                "version": version,
                "purl": purl,
                "ecosystem": ecosystem,
                "package_name": package_name,
            },
        })
    return queries, skipped


def post_json(url: str, payload: dict[str, Any], timeout: float, retries: int = 3) -> dict[str, Any]:
    raw = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            message = exc.read(1000).decode("utf-8", errors="replace")
            last_error = RuntimeError(f"OSV API returned HTTP {exc.code}: {message}")
            if exc.code not in (429, 500, 502, 503, 504) or attempt == retries - 1:
                raise last_error from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == retries - 1:
                raise RuntimeError(f"OSV API request failed: {exc}") from exc
        time.sleep(1.0 * (attempt + 1))
    raise RuntimeError(f"OSV API request failed: {last_error}")


def advisory_summary(vuln: dict[str, Any]) -> dict[str, Any]:
    refs = vuln.get("references") or []
    urls = [x.get("url") for x in refs if isinstance(x, dict) and x.get("url")]
    severities = vuln.get("severity") or []
    severity_labels = []
    for item in severities:
        if isinstance(item, dict):
            score = item.get("score")
            kind = item.get("type")
            if score:
                severity_labels.append({"type": kind, "score": score})
    affected = vuln.get("affected") or []
    return {
        "id": vuln.get("id"),
        "summary": vuln.get("summary"),
        "details_excerpt": (vuln.get("details") or "")[:500],
        "modified": vuln.get("modified"),
        "published": vuln.get("published"),
        "aliases": vuln.get("aliases") or [],
        "severity": severity_labels,
        "reference_urls": urls[:10],
        "database_specific": vuln.get("database_specific") or {},
        "affected_entries": len(affected),
    }


def run_validation(sbom_path: Path, out_path: Path, timeout: float, batch_size: int) -> dict[str, Any]:
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"SBOM file not found: {sbom_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"SBOM is not valid JSON: {exc}") from exc
    if not isinstance(sbom, dict):
        raise ValueError("SBOM root must be a JSON object")
    if "bomFormat" in sbom and sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("Input does not declare bomFormat=CycloneDX")

    queries, skipped = extract_queries(sbom)
    components_checked: list[dict[str, Any]] = []
    api_errors: list[str] = []

    for offset in range(0, len(queries), batch_size):
        chunk = queries[offset:offset + batch_size]
        # Strip internal metadata before sending the request to OSV.
        payload_queries = [{k: v for k, v in item.items() if not k.startswith("_")} for item in chunk]
        try:
            response = post_json(OSV_QUERYBATCH_URL, {"queries": payload_queries}, timeout)
            results = response.get("results", [])
            if not isinstance(results, list) or len(results) != len(chunk):
                raise RuntimeError("OSV response results count did not match batch query count")
            for query, result in zip(chunk, results):
                metadata = query["_component"]
                vulns = result.get("vulns") or [] if isinstance(result, dict) else []
                components_checked.append({
                    **metadata,
                    "advisory_count": len(vulns),
                    "advisories": [advisory_summary(v) for v in vulns if isinstance(v, dict)],
                    "lookup_status": "matched_advisories" if vulns else "no_advisory_returned",
                })
        except Exception as exc:  # preserve partial results and visibly flag failures
            message = f"Batch starting at component {offset + 1} failed: {exc}"
            api_errors.append(message)
            for query in chunk:
                components_checked.append({
                    **query["_component"],
                    "advisory_count": None,
                    "advisories": [],
                    "lookup_status": "api_error",
                    "error": str(exc),
                })

    # Stable output ordering makes diffing runs easier.
    components_checked.sort(key=lambda c: (str(c.get("ecosystem")), str(c.get("package_name")), str(c.get("version"))))
    affected = [c for c in components_checked if (c.get("advisory_count") or 0) > 0]
    report = {
        "tool": "ChainGuard OSV SBOM Validator",
        "validator_version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "OSV querybatch API",
        "sbom_path": str(sbom_path.resolve()),
        "sbom_serial_number": sbom.get("serialNumber"),
        "sbom_spec_version": sbom.get("specVersion"),
        "summary": {
            "unique_versioned_packages_queried": len(queries),
            "packages_with_advisories": len(affected),
            "advisory_matches_total": sum(int(c.get("advisory_count") or 0) for c in components_checked),
            "api_errors": len(api_errors),
            "components_skipped": len(skipped),
            "components_with_unknown_lookup_status": sum(1 for c in components_checked if c.get("lookup_status") == "api_error"),
        },
        "packages_with_advisories": affected,
        "all_package_results": components_checked,
        "skipped_components": skipped,
        "api_errors": api_errors,
        "interpretation": [
            "This report validates package/version matches against OSV at scan time; advisory data may change.",
            "A returned advisory is not proof that vulnerable code is reachable in the application.",
            "No advisory returned is not proof that a package is safe or vulnerability-free.",
            "Skipped or API-error components are unknown, not clean.",
            "Review advisory ranges, aliases, ecosystem mapping, and package identity before treating a match as confirmed.",
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-check a CycloneDX SBOM against the live OSV API.")
    parser.add_argument("--sbom", required=True, type=Path, help="Path to a CycloneDX JSON SBOM (for example sbom.cdx.json)")
    parser.add_argument("--out", type=Path, default=Path("osv_validation.json"), help="Output JSON path (default: osv_validation.json)")
    parser.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout in seconds (default: 20)")
    parser.add_argument("--batch-size", type=int, default=100, help="Queries per OSV request (1-1000, default: 100)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not 1 <= args.batch_size <= 1000:
        parser.error("--batch-size must be between 1 and 1000")
    try:
        report = run_validation(args.sbom, args.out, args.timeout, args.batch_size)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print("ChainGuard OSV validation complete")
    print(f"Packages queried:          {summary['unique_versioned_packages_queried']}")
    print(f"Packages with advisories:  {summary['packages_with_advisories']}")
    print(f"Advisory matches:          {summary['advisory_matches_total']}")
    print(f"API errors:                {summary['api_errors']}")
    print(f"Skipped components:        {summary['components_skipped']}")
    print(f"Report:                    {args.out.resolve()}")
    # 0 = completed with no API errors, 1 = completed but partial/unknown, 2 = input/runtime failure.
    if summary["api_errors"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

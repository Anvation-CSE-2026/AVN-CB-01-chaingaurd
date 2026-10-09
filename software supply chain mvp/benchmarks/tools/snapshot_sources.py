"""Snapshot the public vulnerability and registry facts the benchmark depends on.

Run this once (or to refresh the corpus). Its output,
``benchmarks/manifests/source_snapshot.json``, is committed so that the corpus
build and the ground truth are reproducible offline. Every value is recorded
with the exact URL it came from. A failed registry lookup is stored as ``null``
(unknown) and is never guessed; the build refuses to proceed on unknowns.

Usage:  python benchmarks/tools/snapshot_sources.py
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote

import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from corpus_spec import CASES  # noqa: E402

OUT = HERE.parent / "manifests" / "source_snapshot.json"
OSV = "https://api.osv.dev/v1"
TIMEOUT = 60
ATTEMPTS = 4


def _get(url: str, **kwargs):
    last = None
    for attempt in range(ATTEMPTS):
        try:
            return requests.get(url, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as error:  # transient registry flakiness
            last = error
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"GET failed after {ATTEMPTS} attempts: {url}: {last}")


def collect_coordinates() -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
    pins, names = set(), set()
    for case in CASES:
        for eco, name, version in case["pins"]:
            pins.add((eco, name, version))
            names.add((eco, name))
    return sorted(pins), sorted(names)


def osv_query(pins):
    payload = {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v}
                           for e, n, v in pins]}
    for attempt in range(ATTEMPTS):
        try:
            response = requests.post(f"{OSV}/querybatch", json=payload, timeout=TIMEOUT)
            response.raise_for_status()
            return response.json()["results"]
        except requests.RequestException:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("OSV querybatch failed after retries")


def osv_advisory(advisory_id: str) -> dict:
    response = _get(f"{OSV}/vulns/{advisory_id}")
    response.raise_for_status()
    data = response.json()
    return {"id": data.get("id"), "aliases": sorted(data.get("aliases", [])),
            "summary": data.get("summary"), "details": data.get("details", ""),
            "modified": data.get("modified"), "source": f"{OSV}/vulns/{advisory_id}"}


def registry_exists(ecosystem: str, name: str) -> dict:
    if ecosystem == "PyPI":
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/json"
        response = _get(url)
        if response.status_code == 404:
            return {"exists": False, "status": 404, "source": url}
        response.raise_for_status()
        return {"exists": True, "status": response.status_code, "source": url}
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{quote(name, safe='@/')}"
        response = _get(url)
        if response.status_code == 404:
            return {"exists": False, "status": 404, "source": url}
        response.raise_for_status()
        return {"exists": True, "status": response.status_code, "source": url}
    if ecosystem == "Maven":
        group, artifact = name.split(":", 1)
        params = {"q": f'g:"{group}" AND a:"{artifact}"', "rows": 1, "wt": "json"}
        response = _get("https://search.maven.org/solrsearch/select", params=params)
        response.raise_for_status()
        found = response.json().get("response", {}).get("numFound", 0)
        return {"exists": found > 0, "status": response.status_code, "num_found": found,
                "source": "https://search.maven.org/solrsearch/select?" + "q=" + quote(params["q"])}
    return {"exists": None, "status": None, "source": None, "error": f"unsupported {ecosystem}"}


def main() -> int:
    pins, names = collect_coordinates()
    print(f"coordinates: {len(pins)} pinned versions, {len(names)} registry names")

    results = osv_query(pins)
    query_ids: dict[str, list[str]] = {}
    for (eco, name, version), result in zip(pins, results):
        key = f"{eco}|{name}|{version}"
        query_ids[key] = sorted({v["id"] for v in result.get("vulns", []) if v.get("id")})
    advisory_ids = sorted({i for ids in query_ids.values() for i in ids})
    print(f"OSV: {len(advisory_ids)} distinct advisories")

    advisories = {}
    for advisory_id in advisory_ids:
        advisories[advisory_id] = osv_advisory(advisory_id)

    registry = {}
    for eco, name in names:
        registry[f"{eco}|{name}"] = registry_exists(eco, name)
        print(f"registry {eco} {name}: exists={registry[f'{eco}|{name}']['exists']}")

    snapshot = {
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "osv_api": OSV,
        "osv_queries": query_ids,
        "osv_advisories": advisories,
        "registry": registry,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

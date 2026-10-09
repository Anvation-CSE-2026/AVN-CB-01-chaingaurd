"""Dependency name existence and slopsquatting heuristics."""
from __future__ import annotations

import datetime as dt
import json
import re
import time
from typing import Any
from urllib.parse import quote

try:
    import requests
except ImportError:  # network-based checks are unavailable without the optional runtime
    requests = None

POPULAR = {
    "PyPI": "requests urllib3 numpy pandas django flask fastapi sqlalchemy pyyaml pillow beautifulsoup4 pytest boto3 cryptography tensorflow torch scipy scikit-learn matplotlib jupyter click pydantic celery redis httpx aiohttp django-rest-framework paramiko pyjwt sqlalchemy-utils lxml scrapy tornado werkzeug jinja2 six setuptools wheel pip protobuf opencv-python python-dateutil attrs rich typer black mypy",
    "npm": "react react-dom next express lodash axios typescript webpack vite eslint prettier chalk commander yargs debug uuid moment dayjs date-fns jest mocha vitest dotenv zod prisma mongoose pg mysql2 redis cors body-parser tailwindcss @types/node @babel/core @testing-library/react redux zustand rxjs webpack-cli esbuild rollup gulp grunt jquery angular vue svelte fastify koa socket.io",
    "Maven": "junit org.springframework:spring-core org.springframework:spring-web org.springframework.boot:spring-boot-starter junit:junit com.google.guava:guava com.fasterxml.jackson.core:jackson-databind org.apache.commons:commons-lang3 org.slf4j:slf4j-api log4j:log4j org.apache.logging.log4j:log4j-core org.yaml:snakeyaml com.squareup.okhttp3:okhttp org.apache.httpcomponents:httpclient mysql:mysql-connector-java org.postgresql:postgresql",
}


def _tokens(ecosystem: str) -> list[str]:
    if ecosystem == "Maven":
        return [x for x in POPULAR[ecosystem].split() if ":" in x]
    return POPULAR.get(ecosystem, "").split()


def edit_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        left, right = right, left
    previous = list(range(len(right) + 1))
    for i, a in enumerate(left, 1):
        current = [i]
        for j, b in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (a != b)))
        previous = current
    return previous[-1]


def _registry(package: dict[str, str]) -> tuple[bool | None, dt.datetime | None, int | None, str | None]:
    ecosystem, name = package["ecosystem"], package["name"]
    if requests is None:
        return None, None, None, "Registry lookup unavailable (requests is not installed)"
    try:
        if ecosystem == "PyPI":
            response = requests.get(f"https://pypi.org/pypi/{quote(name, safe='')}/json", timeout=15)
            if response.status_code == 404:
                return False, None, 0, "PyPI returned 404"
            response.raise_for_status()
            payload = response.json()
            times = []
            for files in payload.get("releases", {}).values():
                for file in files:
                    stamp = file.get("upload_time_iso_8601") or file.get("upload_time")
                    if stamp:
                        try:
                            times.append(dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")))
                        except ValueError:
                            pass
            return True, min(times) if times else None, len(payload.get("releases", {})), None
        if ecosystem == "npm":
            response = requests.get(f"https://registry.npmjs.org/{quote(name, safe='@/')}", timeout=15)
            if response.status_code == 404:
                return False, None, 0, "npm registry returned 404"
            response.raise_for_status()
            payload = response.json()
            created = payload.get("time", {}).get("created")
            when = dt.datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None
            return True, when, len(payload.get("versions", {})), None
        group, artifact = name.split(":", 1)
        response = requests.get("https://search.maven.org/solrsearch/select",
                                params={"q": f'g:"{group}" AND a:"{artifact}"', "rows": 1000, "wt": "json"}, timeout=15)
        response.raise_for_status()
        metadata = response.json().get("response", {}).get("docs", [])
        if not metadata:
            return False, None, 0, "Maven Central returned no artifact"
        # Request all versions to establish the package's earliest indexed date
        # and release count, rather than treating the default result as history.
        versions_response = requests.get(
            "https://search.maven.org/solrsearch/select",
            params={"q": f'g:"{group}" AND a:"{artifact}"', "core": "gav", "rows": 1000,
                    "fl": "timestamp,v", "wt": "json"}, timeout=15)
        versions_response.raise_for_status()
        docs = versions_response.json().get("response", {}).get("docs", [])
        dates = [dt.datetime.fromtimestamp(doc["timestamp"] / 1000, tz=dt.timezone.utc)
                 for doc in docs if doc.get("timestamp") is not None]
        return True, min(dates) if dates else None, len(docs), None
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None, None, None, "Registry lookup unavailable"


def inspect_package(package: dict[str, str], no_llm: bool = False) -> dict[str, Any]:
    exists, created, release_count, error = _registry(package)
    now = dt.datetime.now(dt.timezone.utc)
    if created and created.tzinfo is None:
        created = created.replace(tzinfo=dt.timezone.utc)
    age_days = (now - created).days if created else None
    normalized = re.sub(r"[^a-z0-9]", "", package["name"].lower())
    close = []
    for popular in _tokens(package["ecosystem"]):
        popular_normalized = re.sub(r"[^a-z0-9]", "", popular.lower())
        if normalized != popular_normalized and abs(len(normalized) - len(popular_normalized)) <= 2:
            distance = edit_distance(normalized, popular_normalized)
            if distance <= 2:
                close.append({"name": popular, "distance": distance})
    reasons = []
    if exists is False:
        reasons.append("package not found in registry")
    if age_days is not None and age_days < 30:
        reasons.append(f"package created {age_days} days ago (<30 days)")
    if (release_count is not None and release_count < 3 and close):
        reasons.append("fewer than 3 releases and name resembles a popular package")
    llm = None
    if not no_llm and (close or exists is False):
        from .llm import package_risk
        llm = package_risk(package["name"], package["ecosystem"])
        if llm and llm["risk"] >= 7:
            reasons.append(f"LLM risk {llm['risk']}/10: {llm['reason']}")
    return {"package": package, "suspicious": bool(reasons), "status": "SUSPICIOUS" if reasons else "ok",
            "exists": exists, "created": created.isoformat() if created else None,
            "age_days": age_days, "release_count": release_count, "similar_names": close,
            "llm": llm, "reasons": reasons, "lookup_error": error}

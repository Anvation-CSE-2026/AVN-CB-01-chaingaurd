"""Manifest discovery and parsing for supported dependency formats.

Design rule: a declaration that cannot be resolved to one concrete version is
never silently discarded. It is reported as an *unresolved dependency* record
(reason + file + raw line) which flows into ``report.json``, ``trace.json`` and
stderr, because a silently dropped unpinned dependency would otherwise produce a
misleading "clean" scan.
"""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import quote

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__"}
SUPPORTED_NAMES = {"requirements.txt", "poetry.lock", "package.json", "pom.xml"}

ECOSYSTEM_BY_FILE = {"requirements.txt": "PyPI", "poetry.lock": "PyPI",
                     "package.json": "npm", "pom.xml": "Maven"}

#: A concrete version starts with a digit and then only version-ish characters;
#: no range operators, wildcards, specifiers or property placeholders.
CONCRETE_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*([.\-+_][A-Za-z0-9.\-+_]*)*$")
WILDCARD_SEGMENTS = {"x", "y", "z", "*", ""}
NON_CONCRETE_KEYWORDS = {"*", "latest", "next", "canary", "dev", "unspecified"}


def _clean(value: str) -> str:
    return value.strip()


def _purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "PyPI":
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        return f"pkg:pypi/{quote(normalized, safe='-._~')}@{quote(version, safe='-._~+') }"
    if ecosystem == "npm":
        npm_name = ("@" + quote(name[1:].split("/", 1)[0], safe='-._~') + "/" +
                    quote(name.split("/", 1)[1], safe='-._~')) if name.startswith("@") and "/" in name else quote(name, safe='-._~')
        return f"pkg:npm/{npm_name}@{quote(version, safe='-._~+') }"
    group, _, artifact = name.partition(":")
    return (f"pkg:maven/{quote(group, safe='-._~')}/"
            f"{quote(artifact, safe='-._~')}@{quote(version, safe='-._~+')}")


def is_concrete_version(version: str) -> bool:
    """True only for a single exact version (no ranges, wildcards, placeholders)."""
    value = _clean(str(version))
    if not value or value.lower() in NON_CONCRETE_KEYWORDS:
        return False
    if not CONCRETE_VERSION.match(value):
        return False
    return all(segment.lower() not in WILDCARD_SEGMENTS for segment in re.split(r"[.\-+_]", value))


def _unresolved(name: str, version_specifier: str, ecosystem: str, reason: str,
                path: Path, raw: str) -> dict[str, Any]:
    return {"name": name, "version_specifier": version_specifier, "ecosystem": ecosystem,
            "reason": reason, "file": str(path), "raw": raw.strip()[:300]}


def _record(name: str, version: str, ecosystem: str) -> dict[str, str] | None:
    name, version = _clean(str(name)), _clean(str(version))
    if not name or not is_concrete_version(version):
        return None
    return {"name": name, "version": version, "ecosystem": ecosystem,
            "purl": _purl(ecosystem, name, version)}


def _parse_requirements_line(line: str, path: Path) -> tuple[dict[str, str] | None, dict[str, Any] | None]:
    raw_line = line
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "--")):
        return None, None
    # `==`, `===` (PEP 440 arbitrary equality) are both accepted as pins.
    pinned_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*={2,3}\s*([^\s;=]+)", line)
    if pinned_match:
        rec = _record(pinned_match.group(1), pinned_match.group(2), "PyPI")
        if rec:
            return rec, None
    pkg_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(.*)$", line)
    if pkg_match:
        name = pkg_match.group(1)
        rest = pkg_match.group(2).strip()
        if not rest or rest.startswith((">=", "<=", ">", "<", "~=", "!=", "===", "@", ";")):
            return None, _unresolved(name, rest or "*", "PyPI",
                                     "unpinned_or_ranged_requirement", path, raw_line)
    return None, _unresolved(raw_line.strip(), "", "PyPI", "malformed_requirement",
                             path, raw_line)


def _requirements_with_diagnostics(path: Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    found = []
    unresolved = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        item, diagnostic = _parse_requirements_line(raw, path)
        if item:
            found.append(item)
        elif diagnostic:
            unresolved.append(diagnostic)
    return found, unresolved


def _requirements(path: Path) -> list[dict[str, str]]:
    packages, _ = _requirements_with_diagnostics(path)
    return packages


def _poetry_with_diagnostics(path: Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    found, unresolved = [], []
    for package in data.get("package", []):
        if not isinstance(package, dict):
            continue
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        item = _record(name, version, "PyPI")
        if item:
            found.append(item)
        elif name:
            unresolved.append(_unresolved(name, version or "*", "PyPI",
                                          "non_concrete_version", path, f"{name}=={version}"))
    return found, unresolved


def _poetry(path: Path) -> list[dict[str, str]]:
    packages, _ = _poetry_with_diagnostics(path)
    return packages


def _package_json_with_diagnostics(path: Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    data: Any = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    found: list[dict[str, str]] = []
    unresolved: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return found, unresolved
    for section in ("dependencies", "devDependencies"):
        entries = data.get(section, {})
        if not isinstance(entries, dict):
            continue
        for name, raw_version in entries.items():
            if not isinstance(raw_version, str):
                unresolved.append(_unresolved(str(name), str(raw_version), "npm",
                                              "non_concrete_version", path,
                                              f"{name}: {raw_version!r}"))
                continue
            requested = raw_version.strip()
            # The requested parser strips the common caret/tilde range prefixes;
            # everything else that is not an exact version is disclosed instead.
            version = re.sub(r"^[~^]\s*", "", requested)
            item = _record(name, version, "npm")
            if item:
                found.append(item)
            else:
                unresolved.append(_unresolved(str(name), requested, "npm",
                                              "non_concrete_version", path,
                                              f"{name}: {requested}"))
    return found, unresolved


def _package_json(path: Path) -> list[dict[str, str]]:
    packages, _ = _package_json_with_diagnostics(path)
    return packages


def _pom_with_diagnostics(path: Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    root = ET.parse(path).getroot()
    found: list[dict[str, str]] = []
    unresolved: list[dict[str, Any]] = []
    for dep in root.iter():
        if dep.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        fields = {}
        for child in dep:
            fields[child.tag.rsplit("}", 1)[-1]] = (child.text or "").strip()
        group, artifact = fields.get("groupId", ""), fields.get("artifactId", "")
        version = fields.get("version", "")
        if not group or not artifact:
            continue
        name = f"{group}:{artifact}"
        if not version:
            unresolved.append(_unresolved(name, "*", "Maven", "missing_version",
                                          path, name))
            continue
        if "${" in version:
            unresolved.append(_unresolved(name, version, "Maven",
                                          "unresolved_maven_property", path, f"{name}:{version}"))
            continue
        item = _record(name, version, "Maven")
        if item:
            found.append(item)
        else:
            unresolved.append(_unresolved(name, version, "Maven",
                                          "non_concrete_version", path, f"{name}:{version}"))
    return found, unresolved


def _pom(path: Path) -> list[dict[str, str]]:
    packages, _ = _pom_with_diagnostics(path)
    return packages


_DIAGNOSTIC_PARSERS = {
    "requirements.txt": _requirements_with_diagnostics,
    "poetry.lock": _poetry_with_diagnostics,
    "package.json": _package_json_with_diagnostics,
    "pom.xml": _pom_with_diagnostics,
}

PARSE_ERRORS = (OSError, ValueError, TypeError, KeyError, ET.ParseError,
                tomllib.TOMLDecodeError, json.JSONDecodeError)


def parse_manifest_with_diagnostics(path: str | Path) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    """Parse one manifest, returning package records plus unresolved declarations."""
    path = Path(path)
    parser = _DIAGNOSTIC_PARSERS.get(path.name)
    if parser is None:
        return [], []
    try:
        return parser(path)
    except PARSE_ERRORS as error:
        return [], [_unresolved(path.name, "", ECOSYSTEM_BY_FILE.get(path.name, "unknown"),
                                "unparseable_manifest", path, str(error))]


def parse_manifest(path: str | Path) -> list[dict[str, str]]:
    """Backward-compatible package-only view of :func:`parse_manifest_with_diagnostics`."""
    return parse_manifest_with_diagnostics(path)[0]


def discover_manifests(root: str | Path) -> list[Path]:
    root = Path(root)
    if root.is_file():
        return [root] if root.name in SUPPORTED_NAMES else []
    manifests = []
    for current, dirs, files in __import__("os").walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if name in SUPPORTED_NAMES:
                manifests.append(Path(current) / name)
    return sorted(manifests)


def parse_manifests_with_diagnostics(paths: list[Path]) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    unique_pkgs: dict[tuple[str, str, str], dict[str, str]] = {}
    unique_unresolved: dict[tuple[str, str, str], dict[str, Any]] = {}
    for path in paths:
        pkgs, unresolved = parse_manifest_with_diagnostics(path)
        for package in pkgs:
            key = (package["ecosystem"], package["name"].lower(), package["version"])
            unique_pkgs[key] = package
        for un in unresolved:
            key = (un["ecosystem"], un["name"].lower(), un.get("version_specifier", ""))
            unique_unresolved[key] = un
    sorted_pkgs = sorted(unique_pkgs.values(), key=lambda item: (item["ecosystem"], item["name"].lower(), item["version"]))
    sorted_unresolved = sorted(unique_unresolved.values(), key=lambda item: (item["ecosystem"], item["name"].lower(), item.get("version_specifier", "")))
    return sorted_pkgs, sorted_unresolved


def parse_manifests(paths: list[Path]) -> list[dict[str, str]]:
    pkgs, _ = parse_manifests_with_diagnostics(paths)
    return pkgs

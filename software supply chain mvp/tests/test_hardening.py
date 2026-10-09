"""Regression tests for the post-implementation audit hardening.

Covers three defects found by the audit:
  * P0 — `git diff`/`git show` used to execute commands configured by the
    *scanned repository* (core.fsmonitor hook, clean/smudge filters, textconv,
    external diff driver).
  * P1 — an LLM answer replaced the advisory-derived function list, so a wrong
    or manipulated answer could suppress a real vulnerable-function call and
    produce a false `not_affected` verdict.
  * P1 — non-concrete versions (ranges, wildcards, `${...}` placeholders) and
    unparseable manifests were represented as exact versions or dropped with no
    record, which can yield a misleading "clean" scan.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from chainguard_mvp.cli import GIT_HARDENING, _decision, _diff_added_packages
from chainguard_mvp.parsers import (discover_manifests, is_concrete_version,
                                    parse_manifest, parse_manifest_with_diagnostics)

PY = str(Path(sys.executable).resolve()).replace("\\", "/")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(repo), check=True,
                          capture_output=True, text=True).stdout.strip()


def _pwn_script(tmp: Path) -> Path:
    """A stand-in for an attacker command: appends its first argument to argv[2]."""
    script = tmp / "pwn.py"
    script.write_text("import sys\nwith open(sys.argv[2], 'a', encoding='utf-8') as fh:\n"
                      "    fh.write(sys.argv[1] + chr(10))\n", encoding="utf-8")
    return script


def _weaponised_repo(tmp: Path, marker: Path, pwn: Path) -> Path:
    """A git repository whose own config/attributes ask git to run `pwn`."""
    repo = tmp / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "package.json").write_text('{"dependencies":{"kept":"1.0.0"}}', encoding="utf-8")
    _git(repo, "add", "package.json")
    _git(repo, "commit", "-qm", "base")
    command = f'"{PY}" "{str(pwn).replace(chr(92), "/")}" TAG "{str(marker).replace(chr(92), "/")}"'

    def cfg(key: str, value: str) -> None:
        _git(repo, "config", key, value)

    cfg("core.fsmonitor", command.replace("TAG", "FSMONITOR"))
    (repo / ".gitattributes").write_text("package.json filter=evil diff=evil\n", encoding="utf-8")
    cfg("filter.evil.clean", command.replace("TAG", "CLEAN"))
    cfg("filter.evil.smudge", command.replace("TAG", "SMUDGE"))
    cfg("filter.evil.required", "true")
    cfg("diff.evil.command", command.replace("TAG", "EXTDIFF"))
    cfg("diff.evil.textconv", command.replace("TAG", "TEXTCONV"))
    cfg("core.pager", command.replace("TAG", "PAGER"))
    cfg("alias.diff", "!" + command.replace("TAG", "ALIAS"))
    # uncommitted change so the diff has worktree content to normalise
    (repo / "package.json").write_text(
        '{"dependencies":{"kept":"1.0.0","added":"2.0.0"}}', encoding="utf-8")
    return repo


def _marker_lines(marker: Path) -> list[str]:
    if not marker.exists():
        return []
    return [line.strip() for line in marker.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------- P0: git hardening

def test_git_hardening_flags_are_present_on_every_scanner_git_call(tmp_path: Path) -> None:
    """Platform-independent guard: the hardened flags must stay in the argv."""
    repo = _weaponised_repo(tmp_path, tmp_path / "marker.txt", _pwn_script(tmp_path))
    base = _git(repo, "rev-parse", "HEAD")
    seen: list[list[str]] = []

    real_run = subprocess.run

    def spy(command, *args, **kwargs):
        seen.append(list(command))
        return real_run(command, *args, **kwargs)

    with patch("chainguard_mvp.cli.subprocess.run", side_effect=spy):
        _diff_added_packages(repo, discover_manifests(repo), base)

    assert len(seen) == 3, seen
    for command in seen:
        assert command[:4] == ["git", "-c", "core.fsmonitor=false", "--no-pager"], command
    diff_command = next(command for command in seen if "diff" in command)
    assert "--no-ext-diff" in diff_command and "--no-textconv" in diff_command
    assert "--cached" in diff_command, "worktree diffs run repository clean filters"
    assert GIT_HARDENING[1] == "core.fsmonitor=false"


def test_scanner_never_executes_repository_configured_commands(tmp_path: Path) -> None:
    """A repo that configures hooks/filters must not get any of them executed."""
    marker = tmp_path / "marker.txt"
    repo = _weaponised_repo(tmp_path, marker, _pwn_script(tmp_path))
    base = _git(repo, "rev-parse", "HEAD")

    # Positive control: the same repository DOES fire its configured commands
    # for a plain `git diff` without the hardening flags (this host executes
    # configured fsmonitor/filter commands; on a host that does not, the
    # assertion below is simply vacuous rather than wrong).
    control = subprocess.run(["git", "diff", "--no-ext-diff", "--unified=0", "HEAD", "--", "package.json"],
                             cwd=str(repo), capture_output=True, text=True, timeout=30)
    control_fired = {line.split()[-1] for line in _marker_lines(marker)}
    assert control.returncode in (0, 128) and "control"  # rc=128 when a required filter fails

    if marker.exists():
        marker.unlink()
    added = _diff_added_packages(repo, discover_manifests(repo), base)

    assert _marker_lines(marker) == [], (
        "scanned repository code executed with " + repr(sorted(control_fired)))
    # diff mode reports only new/changed dependencies; functional behaviour intact
    assert {(item["name"], item["version"]) for item in added} == {("added", "2.0.0")}


def test_diff_mode_still_detects_new_versions_with_a_clean_repository(tmp_path: Path) -> None:
    repo = tmp_path / "clean"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    _git(repo, "add", "requirements.txt")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "requirements.txt").write_text("requests==2.19.0\nflask==2.0.0\n", encoding="utf-8")

    added = _diff_added_packages(repo, discover_manifests(repo), base)
    assert [item["name"] for item in added] == ["flask"]


# --------------------------------------------------------------- P1: LLM union guard

ADVISORY = ("A vulnerability in PyYAML allows arbitrary code execution when input is "
            "processed through the full_load method or FullLoader. `yaml.load` is unsafe.")

VULNERABILITY = {
    "id": "GHSA-test-0001", "aliases": [], "summary": "PyYAML unsafe load",
    "details": "untrusted input", "severity": [], "fixed_version": None,
    "package": {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI",
                "purl": "pkg:pypi/pyyaml@5.3"},
    "advisory_text": ADVISORY,
}

CALLS_LOAD = "import yaml\n\ndef parse(payload):\n    return yaml.load(payload)\n"
CALLS_SAFE_LOAD = "import yaml\n\ndef parse(payload):\n    return yaml.safe_load(payload)\n"


def _decide(tmp: Path, source: str, llm_result) -> dict:
    (tmp / "app.py").write_text(source, encoding="utf-8")
    with patch("chainguard_mvp.cli.vulnerable_functions", return_value=llm_result):
        record, _ = _decision(VULNERABILITY, tmp, no_llm=False)
    return record


def test_llm_wrong_function_list_cannot_suppress_a_real_call(tmp_path: Path) -> None:
    record = _decide(tmp_path, CALLS_LOAD,
                     {"vulnerable_functions": ["irrelevant_helper"], "confidence": 0.99})
    assert record["status"] == "affected", record["impact_statement"]
    assert "yaml.load" in record["evidence"]["vulnerable_functions"]
    assert record["evidence"]["function_source"] == "llm+advisory_backticks"


def test_llm_can_only_add_function_candidates(tmp_path: Path) -> None:
    record = _decide(tmp_path, CALLS_SAFE_LOAD,
                     {"vulnerable_functions": ["totally_custom_sink"], "confidence": 0.8})
    assert {"totally_custom_sink", "yaml.load", "yaml.full_load"} <= set(
        record["evidence"]["vulnerable_functions"])
    # neither the added name nor the deterministic ones are called here
    assert record["status"] == "not_affected"
    assert record["evidence"]["confidence"] == 0.8


def test_llm_empty_function_list_falls_back_to_advisory_heuristics(tmp_path: Path) -> None:
    record = _decide(tmp_path, CALLS_SAFE_LOAD,
                     {"vulnerable_functions": [], "confidence": 0.4})
    functions = record["evidence"]["vulnerable_functions"]
    assert "yaml.load" in functions, "heuristic extraction must still run"
    assert record["evidence"]["function_source"] == "advisory_backticks"
    assert record["evidence"]["confidence"] is None
    assert record["status"] == "not_affected"


def test_no_llm_still_uses_the_advisory_path_unchanged(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(CALLS_LOAD, encoding="utf-8")
    with patch("chainguard_mvp.cli.vulnerable_functions",
               side_effect=AssertionError("LLM must not be called with --no-llm")):
        record, _ = _decision(VULNERABILITY, tmp_path, no_llm=True)
    assert record["status"] == "affected"
    assert record["evidence"]["function_source"] == "advisory_backticks"


# --------------------------------------------------------------- P1: parser disclosure

def _write(tmp: Path, name: str, text: str) -> Path:
    path = tmp / name
    path.write_text(text, encoding="utf-8")
    return path


def test_non_concrete_versions_are_rejected_and_disclosed(tmp_path: Path) -> None:
    path = _write(tmp_path, "package.json", json.dumps({"dependencies": {
        "lodash": "4.17.15", "express": ">=4.0.0", "chalk": "5.x", "local": "workspace:*"}}))
    packages, unresolved = parse_manifest_with_diagnostics(path)

    assert [(p["name"], p["version"]) for p in packages] == [("lodash", "4.17.15")]
    assert {u["reason"] for u in unresolved} == {"non_concrete_version"}
    assert {u["name"] for u in unresolved} == {"express", "chalk", "local"}
    assert all(u["file"].endswith("package.json") for u in unresolved)


def test_maven_property_placeholder_is_disclosed_not_guessed(tmp_path: Path) -> None:
    path = _write(tmp_path, "pom.xml", """<?xml version="1.0"?>
<project><dependencies>
  <dependency><groupId>com.example</groupId><artifactId>lib</artifactId>
    <version>${my.version}</version></dependency>
  <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>
    <version>31.1-jre</version></dependency>
</dependencies></project>""")
    packages, unresolved = parse_manifest_with_diagnostics(path)

    assert [p["name"] for p in packages] == ["com.google.guava:guava"]
    assert len(unresolved) == 1
    assert unresolved[0]["reason"] == "unresolved_maven_property"
    assert unresolved[0]["version_specifier"] == "${my.version}"


def test_unparseable_manifest_is_disclosed(tmp_path: Path) -> None:
    path = _write(tmp_path, "package.json", "{not json")
    packages, unresolved = parse_manifest_with_diagnostics(path)

    assert packages == []
    assert len(unresolved) == 1 and unresolved[0]["reason"] == "unparseable_manifest"
    assert parse_manifest(path) == []          # package-only view is unchanged


def test_requirements_arbitrary_equality_pin_is_accepted(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", "requests===2.31.0\nflask>=2\n")
    packages, unresolved = parse_manifest_with_diagnostics(path)

    assert [(p["name"], p["version"]) for p in packages] == [("requests", "2.31.0")]
    assert [u["reason"] for u in unresolved] == ["unpinned_or_ranged_requirement"]


def test_concrete_version_predicate() -> None:
    for good in ("1.0.0", "4.17.15", "31.1-jre", "1.0.0-rc.1", "1.0.0+build.5", "2024.1"):
        assert is_concrete_version(good), good
    for bad in (">=4.0.0", "^1.2.3", "~1.0", "5.x", "*", "latest", "${my.version}",
                "workspace:*", "file:../x", "git+https://example.invalid/x", "", "  "):
        assert not is_concrete_version(bad), bad

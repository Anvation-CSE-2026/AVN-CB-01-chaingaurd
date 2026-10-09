"""Build the ChainBench-100 corpus from corpus_spec.py and the committed snapshot.

Deterministic and offline: it reads manifests/source_snapshot.json and never
touches the network. Any consistency failure aborts the build, so an
inconsistent ground truth can never be published.

Usage:  python benchmarks/tools/build_corpus.py
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from corpus_spec import ADVISORY_FUNCTIONS, CASES  # noqa: E402

BENCH = HERE.parent
CASES_DIR = BENCH / "cases"
MANIFESTS = BENCH / "manifests"
SNAPSHOT = MANIFESTS / "source_snapshot.json"

CATEGORY_DIR = {
    "clean": "clean", "vulnerable": "vulnerable", "reachable": "reachable",
    "unreachable": "unreachable", "suspicious": "suspicious", "slopsquatting": "slopsquatting",
    "dependency_confusion": "dependency_confusion", "unpinned": "unpinned",
    "lockfile_mismatch": "lockfile_mismatch", "mixed": "mixed", "unsupported": "unsupported",
}

ECOSYSTEM_BY_FILE = {
    "requirements.txt": "PyPI", "poetry.lock": "PyPI", "pyproject.toml": "PyPI",
    "Pipfile.lock": "PyPI", "package.json": "npm", "package-lock.json": "npm",
    "pom.xml": "Maven", "Cargo.toml": "crates.io", "go.mod": "Go", "Gemfile.lock": "RubyGems",
}

ERRORS: list[str] = []


def fail(case_id: str, message: str) -> None:
    ERRORS.append(f"{case_id}: {message}")


def advisory_url(advisory_id: str) -> str:
    return f"https://api.osv.dev/v1/vulns/{advisory_id}"


def build_truth(case: dict, snapshot: dict) -> dict:
    cid = case["case_id"]
    imports = {i.lower() for i in case["imports"]}
    calls = {k.lower(): v for k, v in case["calls"].items()}
    dead = {k.lower(): v for k, v in case["dead_calls"].items()}
    ghosts = set(case["ghost"])
    pin_names = {name for _, name, _ in case["pins"]}
    for ghost in ghosts:
        if ghost not in pin_names:
            fail(cid, f"ghost {ghost!r} is not a pinned name")

    vulnerabilities, seen = [], set()
    for eco, name, version in case["pins"]:
        registry = snapshot["registry"].get(f"{eco}|{name}")
        if registry is None or registry.get("exists") is None:
            fail(cid, f"registry status unknown for {eco} {name}")
        else:
            expected_exists = name not in ghosts
            if registry["exists"] != expected_exists:
                fail(cid, f"registry says {name} exists={registry['exists']} but spec says {expected_exists}")
        ids = snapshot["osv_queries"].get(f"{eco}|{name}|{version}")
        if ids is None:
            fail(cid, f"no OSV snapshot entry for {eco} {name}@{version}")
            continue
        for advisory_id in ids:
            key = (advisory_id, name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            advisory = snapshot["osv_advisories"][advisory_id]
            functions = ADVISORY_FUNCTIONS.get(advisory_id, [])
            name_lower = name.lower()
            hits: list[str] = []
            if name_lower not in imports:
                label, status, justification = "UNREACHABLE", "not_affected", "vulnerable_code_not_present"
            elif not functions:
                label, status, justification = "UNDETERMINED", "affected", None
            else:
                hits = [f for f in functions if f in calls.get(name_lower, [])]
                if hits:
                    label, status, justification = "REACHABLE", "affected", None
                else:
                    label, status, justification = ("UNREACHABLE", "not_affected",
                                                    "vulnerable_code_not_in_execute_path")
            vulnerabilities.append({
                "id": advisory_id, "aliases": advisory["aliases"], "ecosystem": eco,
                "package": name, "version": version, "label": label,
                "expected_status": status, "expected_justification": justification,
                "advisory_functions": functions, "called_functions": hits,
                "dead_code_functions": dead.get(name_lower, []) if label != "REACHABLE" else [],
                "source": advisory_url(advisory_id),
            })
    vulnerabilities.sort(key=lambda v: (v["package"].lower(), v["version"], v["id"]))

    actionable = any(v["expected_status"] == "affected" for v in vulnerabilities)
    if vulnerabilities:
        base = "ACTIONABLE" if actionable else "DISMISSED"
    else:
        base = "CLEAN"
    if ghosts:
        verdict = "SUSPICIOUS" if base == "CLEAN" else f"{base}+SUSPICIOUS"
    else:
        verdict = base
    exit_code = 1 if ("ACTIONABLE" in verdict or "SUSPICIOUS" in verdict) else 0

    reachable = [{"id": v["id"], "package": v["package"], "version": v["version"],
                  "vulnerable_function": v["called_functions"], "call_path": case["call_path"]}
                 for v in vulnerabilities if v["label"] == "REACHABLE"]
    unreachable = [{"id": v["id"], "package": v["package"], "version": v["version"],
                    "reason": v["expected_justification"], "dead_code_functions": v["dead_code_functions"]}
                   for v in vulnerabilities if v["label"] == "UNREACHABLE"]
    return {
        "vulnerabilities": vulnerabilities,
        "reachable": reachable,
        "unreachable": unreachable,
        "undetermined": [{"id": v["id"], "package": v["package"]}
                         for v in vulnerabilities if v["label"] == "UNDETERMINED"],
        "suspicious_packages": sorted(ghosts),
        "checked_packages": sorted({f"{e}|{n}" for e, n, _ in case["pins"]}),
        "dependency_disclosures": [{"name": n, "allowed_reasons": r} for n, r in case["disclosures"]],
        "expected_verdict": verdict,
        "expected_exit_code": exit_code,
    }


def check_category(case: dict, truth: dict) -> None:
    cid, cat = case["case_id"], case["category"]
    vulns = truth["vulnerabilities"]
    if cat == "clean" and (vulns or truth["suspicious_packages"] or truth["dependency_disclosures"]):
        fail(cid, "clean case has findings or disclosures")
    if cat == "vulnerable" and not vulns:
        fail(cid, "vulnerable case has no advisories in the snapshot")
    if cat == "reachable" and not truth["reachable"]:
        fail(cid, "reachable case has no REACHABLE label")
    if cat == "unreachable":
        if not vulns:
            fail(cid, "unreachable case has no advisories")
        if truth["reachable"]:
            fail(cid, "unreachable case contains a REACHABLE label")
    if cat == "suspicious" and not truth["suspicious_packages"]:
        fail(cid, "suspicious case has no ghost package")
    if cat == "unsupported" and case["supported"]:
        fail(cid, "unsupported category case marked supported")
    if cat != "unsupported" and not case["supported"]:
        fail(cid, "supported=False outside the unsupported category")


def check_fixture_text(case: dict) -> None:
    cid = case["case_id"]
    text = "\n".join(content for content in case["files"].values()).lower()
    for eco, name, version in case["pins"]:
        artifact = name.split(":", 1)[-1].lower()
        if artifact not in text:
            fail(cid, f"pinned name {name} not present in fixture files")
        if version.lower() not in text:
            fail(cid, f"pinned version {version} for {name} not present in fixture files")
    for name, _ in case["disclosures"]:
        if name.split(":", 1)[-1].lower() not in text:
            fail(cid, f"disclosure subject {name} not present in fixture files")
    for path in case["files"]:
        if path.startswith("/") or ".." in Path(path).parts:
            fail(cid, f"unsafe fixture path {path}")


def evidence_lines(truth: dict) -> list[str]:
    lines = []
    for v in truth["vulnerabilities"]:
        if v["label"] == "REACHABLE":
            lines.append(f"{v['id']} ({v['package']}@{v['version']}): call to {v['called_functions']} "
                         f"recorded in calls evidence; status affected")
        elif v["label"] == "UNDETERMINED":
            lines.append(f"{v['id']} ({v['package']}@{v['version']}): import evidence present; "
                         f"no function data -> conservative affected")
        elif v["expected_justification"] == "vulnerable_code_not_present":
            lines.append(f"{v['id']} ({v['package']}@{v['version']}): no import evidence; "
                         f"status not_affected (vulnerable_code_not_present)")
        else:
            lines.append(f"{v['id']} ({v['package']}@{v['version']}): import evidence with no vulnerable "
                         f"call; status not_affected (vulnerable_code_not_in_execute_path)")
    for name in truth["suspicious_packages"]:
        lines.append(f"{name}: suspicious with a 'package not found in registry' reason")
    for d in truth["dependency_disclosures"]:
        lines.append(f"{d['name']}: disclosed as one of {d['allowed_reasons']} in unresolved_dependencies")
    return lines


def write_case(case: dict, truth: dict, snapshot: dict) -> dict:
    cid = case["case_id"]
    rel = Path("cases") / CATEGORY_DIR[case["category"]] / cid
    root = BENCH / rel
    repo = root / "repo"
    for path, content in case["files"].items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    ecosystems = sorted({ECOSYSTEM_BY_FILE[Path(p).name] for p in case["files"]
                         if Path(p).name in ECOSYSTEM_BY_FILE})
    metadata = {
        "case_id": cid,
        "category": case["category"],
        "ecosystem": ecosystems or ["none"],
        "description": case["description"],
        "fixture_path": (rel / "repo").as_posix(),
        "pins": [{"ecosystem": e, "name": n, "version": v} for e, n, v in case["pins"]],
        "imports": case["imports"],
        "calls": case["calls"],
        "dead_calls": case["dead_calls"],
        "ground_truth": truth,
        "expected_verdict": truth["expected_verdict"],
        "expected_exit_code": truth["expected_exit_code"],
        "expected_evidence": evidence_lines(truth),
        "dependency_disclosures": truth["dependency_disclosures"],
        "rationale": case["rationale"],
        "call_path": case["call_path"],
        "supported": case["supported"],
        "engine_boundary": case["engine_boundary"],
        "assert_reachability": case["assert_reachability"],
        "assert_verdict": case["assert_verdict"],
        "network_required": bool(case["pins"] or case["ghost"]),
        "safe_fixture": True,
        "ground_truth_sources": {
            "advisories": "OSV (manifests/source_snapshot.json osv_advisories)",
            "registry": "PyPI/npm/Maven Central (manifests/source_snapshot.json registry)",
            "function_truth": "curated from advisory text in tools/corpus_spec.py ADVISORY_FUNCTIONS",
            "reachability_truth": "authored from fixture design in tools/corpus_spec.py",
        },
    }
    (root / "case.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (root / "README.md").write_text(readme(case, truth), encoding="utf-8")
    return {"case_id": cid, "category": case["category"], "path": rel.as_posix(),
            "supported": case["supported"], "expected_verdict": truth["expected_verdict"],
            "engine_boundary": case["engine_boundary"]}


def readme(case: dict, truth: dict) -> str:
    lines = [f"# {case['case_id']} ({case['category']})", "", case["description"], "",
             f"- **Expected verdict:** `{truth['expected_verdict']}` (exit `{truth['expected_exit_code']}`)",
             f"- **Supported by engine:** {case['supported']}",
             f"- **Engine boundary probed:** {case['engine_boundary'] or 'none'}",
             "", "## Rationale", "", case["rationale"], ""]
    if case["call_path"]:
        lines += ["## Expected call path", "", f"`{case['call_path']}`", ""]
    if truth["vulnerabilities"]:
        lines += ["## Ground-truth advisories", "",
                  "| advisory | package | version | label | expected status |",
                  "|---|---|---|---|---|"]
        for v in truth["vulnerabilities"]:
            lines.append(f"| {v['id']} | {v['package']} | {v['version']} | {v['label']} | "
                         f"{v['expected_status']} |")
        lines.append("")
    lines += ["## Reproduce", "", "```sh",
              "python benchmarks/runner/run_benchmark.py --case " + case["case_id"], "```", ""]
    return "\n".join(lines)


def main() -> int:
    snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    if CASES_DIR.exists():
        shutil.rmtree(CASES_DIR)
    CASES_DIR.mkdir(parents=True)
    truths, index = [], []
    ids = set()
    for case in CASES:
        cid = case["case_id"]
        if cid in ids:
            fail(cid, "duplicate case id")
        ids.add(cid)
        check_fixture_text(case)
        truth = build_truth(case, snapshot)
        check_category(case, truth)
        truths.append((case, truth))

    if ERRORS:
        print("BUILD FAILED:")
        for message in ERRORS:
            print("  -", message)
        return 1

    for case, truth in truths:
        index.append(write_case(case, truth, snapshot))

    MANIFESTS.mkdir(parents=True, exist_ok=True)
    (MANIFESTS / "benchmark_index.json").write_text(
        json.dumps({"corpus": "ChainBench-100", "case_count": len(index), "cases": index}, indent=2) + "\n",
        encoding="utf-8")
    (MANIFESTS / "ground_truth.json").write_text(
        json.dumps({"corpus": "ChainBench-100", "source_snapshot": "manifests/source_snapshot.json",
                    "snapshot_generated_utc": snapshot["generated_utc"],
                    "cases": {case["case_id"]: truth for case, truth in truths}}, indent=2) + "\n",
        encoding="utf-8")
    print(f"built {len(index)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

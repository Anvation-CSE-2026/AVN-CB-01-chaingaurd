"""ChainBench-100 runner.

For each case it:
  1. validates case.json against the required contract,
  2. runs the canonical engine with list argv (no shell) into its own output dir
     benchmarks/.runs/<case_id>/, capturing stdout, stderr, exit code and time,
  3. validates the four canonical artifacts,
  4. compares the actual report to the independent ground truth,
  5. writes manifests/benchmark_results.json.

Scoring and report generation live in runner/score.py.

Usage:
  python benchmarks/runner/run_benchmark.py                 # all cases
  python benchmarks/runner/run_benchmark.py --case CB-REACH-001 --case CB-MIX-002
  python benchmarks/runner/run_benchmark.py --category reachable
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
ENGINE_ROOT = BENCH.parent  # "software supply chain mvp": contains chainguard_mvp/
RUNS = BENCH / ".runs"
MANIFESTS = BENCH / "manifests"
RESULTS = MANIFESTS / "benchmark_results.json"

REQUIRED_CASE_KEYS = {
    "case_id": str, "category": str, "ecosystem": list, "description": str,
    "fixture_path": str, "pins": list, "imports": list, "calls": dict, "dead_calls": dict,
    "ground_truth": dict, "expected_verdict": str, "expected_exit_code": int,
    "expected_evidence": list, "rationale": str, "supported": bool, "engine_boundary": (str, type(None)),
    "assert_reachability": bool, "assert_verdict": bool, "network_required": bool, "safe_fixture": bool,
}
REQUIRED_TRUTH_KEYS = {
    "vulnerabilities": list, "reachable": list, "unreachable": list, "undetermined": list,
    "suspicious_packages": list, "checked_packages": list, "dependency_disclosures": list,
    "expected_verdict": str, "expected_exit_code": int,
}
ARTIFACTS = ("report.json", "trace.json", "sbom.cdx.json", "openvex.json")
BASELINE_EXPECTED = {"total_vulnerabilities": 30, "dismissed_unreachable": 26,
                     "actionable": 4, "suspicious_packages": 1, "noise_reduced_percent": 86.7}
RUN_TIMEOUT = 600


def validate_case(meta: dict, path: Path) -> list[str]:
    problems = []
    for key, expected_type in REQUIRED_CASE_KEYS.items():
        if key not in meta:
            problems.append(f"missing key {key}")
        elif not isinstance(meta[key], expected_type):
            problems.append(f"key {key} has wrong type")
    truth = meta.get("ground_truth", {})
    for key, expected_type in REQUIRED_TRUTH_KEYS.items():
        if key not in truth:
            problems.append(f"ground_truth missing {key}")
        elif not isinstance(truth[key], expected_type):
            problems.append(f"ground_truth.{key} has wrong type")
    if meta.get("case_id") and meta["case_id"] != path.parent.name:
        problems.append("case_id does not match its directory name")
    if not (BENCH / meta.get("fixture_path", "")).is_dir():
        problems.append("fixture_path does not exist")
    return problems


def load_cases(selected: set[str], category: str | None) -> list[tuple[dict, Path]]:
    loaded = []
    for path in sorted((BENCH / "cases").glob("*/*/case.json")):
        meta = json.loads(path.read_text(encoding="utf-8"))
        if selected and meta["case_id"] not in selected:
            continue
        if category and meta["category"] != category:
            continue
        problems = validate_case(meta, path)
        if problems:
            raise SystemExit(f"invalid case {path}: {problems}")
        loaded.append((meta, path))
    return loaded


def engine_env() -> dict[str, str]:
    env = dict(os.environ)
    # Benchmark isolation: no LLM calls, and no cdxgen npx download of an external package.
    env["CHAINGUARD_DISABLE_CDXGEN"] = "1"
    for key in ("CHAINGUARD_LLM_ENDPOINT", "CHAINGUARD_LLM_API_KEY", "CHAINGUARD_LLM_MODEL"):
        env.pop(key, None)
    return env


def run_engine(target: Path, out_dir: Path, *, fail_on_actionable: bool, timeout: int) -> dict:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    argv = [sys.executable, "-m", "chainguard_mvp.cli", str(target), "--no-llm",
            "--out-dir", str(out_dir)]
    if fail_on_actionable:
        argv.append("--fail-on-actionable")
    started = time.perf_counter()
    try:
        completed = subprocess.run(argv, cwd=ENGINE_ROOT, capture_output=True, text=True,
                                   timeout=timeout, env=engine_env(), shell=False)
        exit_code, stdout, stderr, timed_out = completed.returncode, completed.stdout, completed.stderr, False
    except subprocess.TimeoutExpired as error:
        exit_code, timed_out = None, True
        stdout = (error.stdout or b"").decode("utf-8", "replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = (error.stderr or b"").decode("utf-8", "replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
    duration = time.perf_counter() - started
    (out_dir / "stdout.txt").write_text(stdout or "", encoding="utf-8")
    (out_dir / "stderr.txt").write_text(stderr or "", encoding="utf-8")
    return {"argv": argv, "exit_code": exit_code, "timed_out": timed_out,
            "duration_seconds": round(duration, 3)}


def check_artifacts(out_dir: Path) -> dict:
    status = {}
    for name in ARTIFACTS:
        path = out_dir / name
        entry = {"present": path.exists(), "parses": False, "bytes": path.stat().st_size if path.exists() else 0}
        if entry["present"]:
            try:
                json.loads(path.read_text(encoding="utf-8"))
                entry["parses"] = True
            except (ValueError, OSError):
                entry["parses"] = False
        status[name] = entry
    report = out_dir / "report.json"
    if report.exists():
        data = json.loads(report.read_text(encoding="utf-8"))
        status["report_schema_version"] = data.get("schema_version")
    sbom = out_dir / "sbom.cdx.json"
    if sbom.exists():
        status["sbom_spec_version"] = json.loads(sbom.read_text(encoding="utf-8")).get("specVersion")
    vex = out_dir / "openvex.json"
    if vex.exists():
        status["openvex_context"] = json.loads(vex.read_text(encoding="utf-8")).get("@context")
    status["complete"] = all(status[name]["present"] and status[name]["parses"] for name in ARTIFACTS)
    return status


def actual_from_report(out_dir: Path) -> dict:
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    findings = []
    for entry in report.get("vulnerabilities", []):
        package = entry["package"]
        findings.append({
            "id": entry["id"], "package": package["name"], "version": package["version"],
            "status": entry["status"], "justification": entry.get("justification"),
            "import_evidence": entry.get("evidence", {}).get("import", []),
            "call_evidence": entry.get("evidence", {}).get("calls", []),
            "total_seen": True,
        })
    suspicious = [{"package": s["package"]["name"], "reasons": s.get("reasons", [])}
                  for s in report.get("suspicious_packages", []) if s.get("suspicious")]
    disclosures = [{"name": d["name"], "reason": d["reason"], "raw": d.get("raw", "")}
                   for d in report.get("unresolved_dependencies", [])]
    return {"findings": findings, "suspicious": suspicious, "disclosures": disclosures,
            "summary": report.get("summary", {})}


def verdict_of(findings: list[dict], suspicious: list[dict]) -> str:
    actionable = any(f["status"] == "affected" for f in findings)
    if findings:
        base = "ACTIONABLE" if actionable else "DISMISSED"
    else:
        base = "CLEAN"
    if suspicious:
        return "SUSPICIOUS" if base == "CLEAN" else f"{base}+SUSPICIOUS"
    return base


def match_disclosures(expected: list[dict], actual: list[dict]) -> tuple[bool, list[str], list[dict]]:
    unmatched = list(actual)
    notes = []
    for item in expected:
        hit = None
        for candidate in unmatched:
            if (item["name"].lower() in candidate["name"].lower()
                    and candidate["reason"] in item["allowed_reasons"]):
                hit = candidate
                break
        if hit is None:
            notes.append(f"missing disclosure {item['name']} {item['allowed_reasons']}")
        else:
            unmatched.remove(hit)
    for extra in unmatched:
        notes.append(f"unexpected disclosure {extra['name']} ({extra['reason']})")
    return (not notes), notes, unmatched


def evaluate(meta: dict, run: dict, actual: dict, artifacts: dict) -> dict:
    truth = meta["ground_truth"]
    notes: list[str] = []
    supported = meta["supported"]

    expected_by_key = {(v["id"], v["package"].lower(), v["version"]): v for v in truth["vulnerabilities"]}
    actual_by_key = {(f["id"], f["package"].lower(), f["version"]): f for f in actual["findings"]}
    expected_keys, actual_keys = set(expected_by_key), set(actual_by_key)
    vuln_tp = sorted(expected_keys & actual_keys)
    vuln_fn = sorted(expected_keys - actual_keys)
    vuln_fp = sorted(actual_keys - expected_keys)
    vuln_ok = not vuln_fn and not vuln_fp

    # Reachability: per-finding status and (for UNREACHABLE) justification.
    reach_details, reach_ok = [], True
    for key, expected in sorted(expected_by_key.items()):
        observed = actual_by_key.get(key)
        observed_status = observed["status"] if observed else None
        observed_just = observed["justification"] if observed else None
        status_ok = observed_status == expected["expected_status"]
        just_ok = (expected["expected_justification"] is None
                   or observed_just == expected["expected_justification"])
        matches = status_ok and just_ok
        reach_details.append({
            "id": key[0], "package": expected["package"], "version": expected["version"],
            "label": expected["label"], "expected_status": expected["expected_status"],
            "actual_status": observed_status, "expected_justification": expected["expected_justification"],
            "actual_justification": observed_just, "matches": matches,
        })
        if expected["label"] in ("REACHABLE", "UNREACHABLE") and not matches:
            reach_ok = False

    # Evidence per expected finding (label-correct findings only are evidence-judged).
    evidence_details = []
    for key, expected in sorted(expected_by_key.items()):
        observed = actual_by_key.get(key)
        if observed is None or not (observed["status"] == expected["expected_status"]):
            continue
        truth_fns = {f.rsplit(".", 1)[-1].lower() for f in expected["advisory_functions"]}
        called = {c["name"].lower() for c in observed["call_evidence"]}
        if expected["label"] == "REACHABLE":
            complete = bool(called & {f.rsplit(".", 1)[-1].lower() for f in expected["called_functions"]})
            present = bool(observed["call_evidence"] or observed["import_evidence"])
        elif expected["label"] == "UNDETERMINED":
            complete = bool(observed["import_evidence"])
            present = complete
        elif expected["expected_justification"] == "vulnerable_code_not_present":
            complete = not observed["import_evidence"]
            present = complete
        else:
            complete = bool(observed["import_evidence"]) and not observed["call_evidence"]
            present = bool(observed["import_evidence"])
        evidence_details.append({"id": key[0], "package": expected["package"], "label": expected["label"],
                                 "evidence_present": present, "evidence_complete": complete,
                                 "truth_functions": sorted(truth_fns)})

    # Suspicious packages.
    expected_susp = {n.lower() for n in truth["suspicious_packages"]}
    actual_susp = {s["package"].lower() for s in actual["suspicious"]}
    susp_ok = expected_susp == actual_susp
    if not susp_ok:
        notes.append(f"suspicious expected {sorted(expected_susp)} got {sorted(actual_susp)}")
    susp_evidence = []
    for expected_name in sorted(expected_susp & actual_susp):
        reasons = next(s["reasons"] for s in actual["suspicious"] if s["package"].lower() == expected_name)
        complete = any("not found" in r for r in reasons)
        susp_evidence.append({"package": expected_name, "evidence_present": bool(reasons),
                              "evidence_complete": complete})

    # Disclosures.
    disc_ok, disc_notes, _ = match_disclosures(truth["dependency_disclosures"], actual["disclosures"])
    notes.extend(disc_notes)

    actual_verdict = verdict_of(actual["findings"], actual["suspicious"])
    verdict_ok = actual_verdict == meta["expected_verdict"]
    exit_ok = run["exit_code"] == meta["expected_exit_code"]
    if meta["assert_verdict"] and not verdict_ok:
        notes.append(f"verdict expected {meta['expected_verdict']} got {actual_verdict}")
    if meta["assert_verdict"] and not exit_ok:
        notes.append(f"exit expected {meta['expected_exit_code']} got {run['exit_code']}")

    checks = {
        "vulnerabilities": vuln_ok,
        "reachability": reach_ok if meta["assert_reachability"] else None,
        "suspicious": susp_ok,
        "disclosures": disc_ok,
        "verdict": verdict_ok if meta["assert_verdict"] else None,
        "exit_code": exit_ok if meta["assert_verdict"] else None,
    }
    label_ok = all(v for v in checks.values() if v is not None)
    evidence_ok = all(e["evidence_complete"] for e in evidence_details + susp_evidence)
    artifacts_ok = artifacts["complete"]

    if run["timed_out"] or run["exit_code"] not in (0, 1) or not artifacts_ok and supported:
        status = "ERROR"
        notes.insert(0, f"run failed: exit={run['exit_code']} timed_out={run['timed_out']} "
                        f"artifacts_complete={artifacts_ok}")
    elif not supported:
        status = "UNSUPPORTED"
        notes.insert(0, "format is outside the engine's parser set; result recorded, not scored")
    elif not label_ok:
        status = "FAIL"
    elif not evidence_ok:
        status = "PARTIAL"
        notes.append("labels correct but evidence incomplete for at least one finding")
    else:
        status = "PASS"

    return {
        "match_status": status,
        "actual_verdict": actual_verdict,
        "checks": checks,
        "notes": notes,
        "vulnerability_matches": {"tp": vuln_tp, "fn": vuln_fn, "fp": vuln_fp},
        "reachability_details": reach_details,
        "evidence_details": evidence_details + susp_evidence,
        "evidence_status": "complete" if evidence_ok else "incomplete",
        "suspicious_expected": sorted(expected_susp),
        "suspicious_actual": sorted(actual_susp),
        "disclosures_expected": truth["dependency_disclosures"],
        "disclosures_actual": actual["disclosures"],
        "engine_summary": actual["summary"],
    }


def run_case(meta: dict, path: Path, timeout: int) -> dict:
    out_dir = RUNS / meta["case_id"]
    target = BENCH / meta["fixture_path"]
    run = run_engine(target, out_dir, fail_on_actionable=True, timeout=timeout)
    base = {"case_id": meta["case_id"], "category": meta["category"], "ecosystem": meta["ecosystem"],
            "supported": meta["supported"], "engine_boundary": meta["engine_boundary"],
            "expected_verdict": meta["expected_verdict"], "expected_exit_code": meta["expected_exit_code"],
            "exit_code": run["exit_code"], "duration_seconds": run["duration_seconds"],
            "output_dir": (out_dir.relative_to(BENCH)).as_posix()}
    artifacts = check_artifacts(out_dir) if out_dir.exists() else {"complete": False}
    base["artifact_status"] = "complete" if artifacts.get("complete") else "incomplete"
    base["artifacts"] = artifacts
    if run["timed_out"] or run["exit_code"] not in (0, 1) or not (out_dir / "report.json").exists():
        base.update({"match_status": "ERROR", "actual_verdict": None, "checks": {},
                     "notes": [f"run failed: exit={run['exit_code']} timed_out={run['timed_out']}"],
                     "expected_findings": [v["id"] for v in meta["ground_truth"]["vulnerabilities"]],
                     "actual_findings": [], "evidence_status": "not_evaluated"})
        return base
    actual = actual_from_report(out_dir)
    result = evaluate(meta, run, actual, artifacts)
    base.update(result)
    base["expected_findings"] = [{"id": v["id"], "package": v["package"], "version": v["version"],
                                  "label": v["label"], "expected_status": v["expected_status"]}
                                 for v in meta["ground_truth"]["vulnerabilities"]]
    base["actual_findings"] = [{"id": f["id"], "package": f["package"], "version": f["version"],
                                "status": f["status"], "justification": f["justification"]}
                               for f in actual["findings"]]
    base["expected_reachability"] = [{"id": r["id"], "package": r["package"], "label": r["label"],
                                      "expected_status": r["expected_status"]}
                                     for r in result["reachability_details"]]
    base["actual_reachability"] = [{"id": r["id"], "package": r["package"], "status": r["actual_status"]}
                                   for r in result["reachability_details"]]
    base["expected_suspicious"] = result["suspicious_expected"]
    base["actual_suspicious"] = result["suspicious_actual"]
    base["expected_disclosures"] = result["disclosures_expected"]
    base["actual_disclosures"] = result["disclosures_actual"]
    base["actual_summary"] = actual["summary"]
    return base


def baseline_check(timeout: int) -> dict:
    target = ENGINE_ROOT / "test_project"
    out_dir = RUNS / "_baseline_test_project"
    run = run_engine(target, out_dir, fail_on_actionable=False, timeout=timeout)
    if run["exit_code"] != 0 or not (out_dir / "report.json").exists():
        return {"status": "ERROR", "exit_code": run["exit_code"], "expected": BASELINE_EXPECTED}
    summary = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))["summary"]
    matches = all(summary.get(k) == v for k, v in BASELINE_EXPECTED.items())
    return {"status": "PASS" if matches else "REGRESSION", "exit_code": run["exit_code"],
            "observed": summary, "expected": BASELINE_EXPECTED, "output_dir": "benchmarks/.runs/_baseline_test_project"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", action="append", default=[], help="run only this case id (repeatable)")
    parser.add_argument("--category", help="run only this category")
    parser.add_argument("--timeout", type=int, default=RUN_TIMEOUT, help="per-run timeout in seconds")
    parser.add_argument("--skip-baseline", action="store_true")
    args = parser.parse_args()

    cases = load_cases(set(args.case), args.category)
    if not cases:
        print("no cases selected")
        return 2
    RUNS.mkdir(exist_ok=True)
    started = dt.datetime.now(dt.timezone.utc)
    results = []
    for index, (meta, path) in enumerate(cases, 1):
        record = run_case(meta, path, args.timeout)
        results.append(record)
        print(f"[{index:3d}/{len(cases)}] {record['case_id']:<16} {record['match_status']:<11} "
              f"exit={record['exit_code']} {record['duration_seconds']:.2f}s")

    baseline = None if args.skip_baseline else baseline_check(args.timeout)
    if baseline:
        print(f"baseline test_project: {baseline['status']}")

    payload = {
        "corpus": "ChainBench-100",
        "run_started_utc": started.isoformat().replace("+00:00", "Z"),
        "run_finished_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "engine_root": "software supply chain mvp",
        "engine_flags": ["--no-llm", "--fail-on-actionable"],
        "environment": {"CHAINGUARD_DISABLE_CDXGEN": "1", "LLM": "disabled"},
        "case_selection": {"cases": args.case, "category": args.category},
        "baseline": baseline,
        "results": results,
    }
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    if args.case or args.category:
        RESULTS.with_suffix(".partial.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"partial results written to {RESULTS.with_suffix('.partial.json').relative_to(BENCH)}")
    else:
        RESULTS.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"results written to {RESULTS.relative_to(BENCH)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

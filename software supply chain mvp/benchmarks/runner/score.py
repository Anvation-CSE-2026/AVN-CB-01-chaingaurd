"""Score ChainBench-100 results and write the metrics, failures and report.

Reads  manifests/benchmark_results.json  (written by run_benchmark.py)
Writes reports/metrics.json, reports/failures.json, reports/benchmark_report.md

Metric definitions (stated once here so the report is auditable):
  * Vulnerability detection: (case, advisory, package, version) tuples compared
    to the ground truth, over supported cases only.
  * Reachability: over findings whose ground-truth label is REACHABLE (positive)
    or UNREACHABLE (negative), in cases that assert reachability. UNDETERMINED
    findings are excluded from precision/recall because the conservative policy
    defines their expected status; they still count in the case checks.
  * Suspicious-package accuracy: every analysed package in supported cases is
    classified suspicious/not, compared to the registry ground truth.
  * Noise reduction: dismissed / total raw findings, computed from the engine's
    actual output and from the ground truth.
  * Scan time: wall-clock duration of each engine process.
"""
from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1]
RESULTS = BENCH / "manifests" / "benchmark_results.json"
REPORTS = BENCH / "reports"
SCHEMA = BENCH / "schema" / "benchmark_case.schema.json"
STATUSES = ["PASS", "PARTIAL", "FAIL", "ERROR", "UNSUPPORTED"]


def prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": _r(precision), "recall": _r(recall), "f1": _r(f1)}


def _r(value):
    return None if value is None else round(value, 4)


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, int(-(-pct * len(ordered) // 100)))  # nearest-rank
    return round(ordered[rank - 1], 3)


def load_truth() -> dict:
    return json.loads((BENCH / "manifests" / "ground_truth.json").read_text(encoding="utf-8"))["cases"]


def main() -> int:
    payload = json.loads(RESULTS.read_text(encoding="utf-8"))
    results = payload["results"]
    truth = load_truth()
    REPORTS.mkdir(exist_ok=True)

    status_counts = Counter(r["match_status"] for r in results)
    evaluated = [r for r in results if r["match_status"] != "UNSUPPORTED"]
    supported_runs = [r for r in results if r["supported"]]

    # Per-category status matrix and accuracy.
    matrix: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        matrix[r["category"]][r["match_status"]] += 1
    per_category = {}
    for category, counts in sorted(matrix.items()):
        eval_n = sum(v for k, v in counts.items() if k != "UNSUPPORTED")
        per_category[category] = {
            "cases": sum(counts.values()), "evaluated": eval_n,
            "status": {s: counts.get(s, 0) for s in STATUSES},
            "pass_accuracy": _r(counts.get("PASS", 0) / eval_n) if eval_n else None,
            "label_accuracy": _r((counts.get("PASS", 0) + counts.get("PARTIAL", 0)) / eval_n) if eval_n else None,
        }

    # Vulnerability detection over supported cases.
    vuln_tp = vuln_fp = vuln_fn = 0
    for r in supported_runs:
        vuln_tp += len(r.get("vulnerability_matches", {}).get("tp", []))
        vuln_fp += len(r.get("vulnerability_matches", {}).get("fp", []))
        vuln_fn += len(r.get("vulnerability_matches", {}).get("fn", []))
    vulnerability = prf(vuln_tp, vuln_fp, vuln_fn)

    # Reachability over labelled findings in reachability-asserting cases.
    reach = Counter()
    reach_boundary = Counter()
    for r in supported_runs:
        if r.get("engine_boundary"):
            bucket = reach_boundary
        else:
            bucket = reach
        for detail in r.get("reachability_details", []):
            if detail["label"] not in ("REACHABLE", "UNREACHABLE"):
                continue
            positive_truth = detail["label"] == "REACHABLE"
            predicted = detail["actual_status"] == "affected"
            if positive_truth and predicted:
                bucket["tp"] += 1
            elif positive_truth and not predicted:
                bucket["fn"] += 1
            elif not positive_truth and predicted:
                bucket["fp"] += 1
            else:
                bucket["tn"] += 1
    overall = {k: reach[k] + reach_boundary[k] for k in ("tp", "fp", "fn", "tn")}
    reachability = prf(overall["tp"], overall["fp"], overall["fn"])
    reachability["tn"] = overall["tn"]
    reachability_excluding_boundary = prf(reach["tp"], reach["fp"], reach["fn"])
    reachability_excluding_boundary["tn"] = reach["tn"]
    reachability_boundary_only = prf(reach_boundary["tp"], reach_boundary["fp"], reach_boundary["fn"])
    reachability_boundary_only["tn"] = reach_boundary["tn"]

    # Noise reduction: engine actual versus ground truth.
    raw_actual = sum(len(r.get("actual_findings", [])) for r in supported_runs)
    actionable_actual = sum(1 for r in supported_runs for f in r.get("actual_findings", [])
                            if f["status"] == "affected")
    raw_truth = sum(len(truth[r["case_id"]]["vulnerabilities"]) for r in supported_runs)
    actionable_truth = sum(1 for r in supported_runs
                           for v in truth[r["case_id"]]["vulnerabilities"] if v["expected_status"] == "affected")
    noise = {
        "raw_findings_actual": raw_actual, "actionable_actual": actionable_actual,
        "dismissed_actual": raw_actual - actionable_actual,
        "noise_reduction_percent_actual": _r((raw_actual - actionable_actual) / raw_actual * 100) if raw_actual else None,
        "raw_findings_truth": raw_truth, "actionable_truth": actionable_truth,
        "noise_reduction_percent_truth": _r((raw_truth - actionable_truth) / raw_truth * 100) if raw_truth else None,
    }

    # Suspicious-package classification over every analysed package.
    susp_tp = susp_fp = susp_fn = susp_tn = 0
    for r in supported_runs:
        checked = set(truth[r["case_id"]]["checked_packages"])
        expected = {n.lower() for n in truth[r["case_id"]]["suspicious_packages"]}
        actual = {n.lower() for n in r.get("actual_suspicious", [])}
        for item in checked:
            name = item.split("|", 1)[1].lower()
            is_truth, is_pred = name in expected, name in actual
            if is_truth and is_pred:
                susp_tp += 1
            elif is_truth:
                susp_fn += 1
            elif is_pred:
                susp_fp += 1
            else:
                susp_tn += 1
    suspicious = prf(susp_tp, susp_fp, susp_fn)
    suspicious["accuracy"] = _r((susp_tp + susp_tn) / (susp_tp + susp_tn + susp_fp + susp_fn)) \
        if (susp_tp + susp_tn + susp_fp + susp_fn) else None
    suspicious["tn"] = susp_tn

    # Dependency-disclosure accuracy.
    disclosure_cases_ok = sum(1 for r in supported_runs if r.get("checks", {}).get("disclosures"))
    expected_items = sum(len(truth[r["case_id"]]["dependency_disclosures"]) for r in supported_runs)
    matched_items = 0
    extra_items = 0
    for r in supported_runs:
        for note in r.get("notes", []):
            if note.startswith("unexpected disclosure"):
                extra_items += 1
    for r in supported_runs:
        expected_names = truth[r["case_id"]]["dependency_disclosures"]
        missing = sum(1 for n in r.get("notes", []) if n.startswith("missing disclosure"))
        matched_items += len(expected_names) - missing
    disclosure = {
        "cases_correct": disclosure_cases_ok, "cases_supported": len(supported_runs),
        "case_accuracy": _r(disclosure_cases_ok / len(supported_runs)) if supported_runs else None,
        "expected_items": expected_items, "matched_items": matched_items,
        "item_recall": _r(matched_items / expected_items) if expected_items else None,
        "unexpected_items": extra_items,
    }

    # Evidence completeness over expected findings and suspicious findings.
    evidence_items = [e for r in supported_runs for e in r.get("evidence_details", [])]
    complete_items = sum(1 for e in evidence_items if e["evidence_complete"])
    evidence = {"items": len(evidence_items), "complete": complete_items,
                "completeness": _r(complete_items / len(evidence_items)) if evidence_items else None}

    # Execution, artifacts, exit codes, timing.
    executed = [r for r in results if r.get("exit_code") is not None]
    exec_ok = [r for r in results if r.get("exit_code") in (0, 1) and r["artifact_status"] == "complete"]
    artifacts_ok = [r for r in results if r["artifact_status"] == "complete"]
    asserted_exit = [r for r in results if r.get("checks", {}).get("exit_code") is not None]
    exit_ok = [r for r in asserted_exit if r["checks"]["exit_code"]]
    durations = [r["duration_seconds"] for r in results if r.get("duration_seconds") is not None]
    execution = {
        "case_execution_success": _r(len(exec_ok) / len(results)) if results else None,
        "artifact_generation_success": _r(len(artifacts_ok) / len(results)) if results else None,
        "exit_code_correctness": _r(len(exit_ok) / len(asserted_exit)) if asserted_exit else None,
        "exit_code_asserted_cases": len(asserted_exit), "runs": len(executed),
        "average_scan_seconds": _r(statistics.mean(durations)) if durations else None,
        "median_scan_seconds": _r(statistics.median(durations)) if durations else None,
        "p95_scan_seconds": percentile(durations, 95),
        "total_scan_seconds": _r(sum(durations)) if durations else None,
    }

    overall_accuracy = _r(status_counts.get("PASS", 0) / len(evaluated)) if evaluated else None
    label_accuracy = _r((status_counts.get("PASS", 0) + status_counts.get("PARTIAL", 0)) / len(evaluated)) \
        if evaluated else None

    metrics = {
        "corpus": payload["corpus"], "cases_total": len(results),
        "cases_evaluated": len(evaluated),
        "status_counts": {s: status_counts.get(s, 0) for s in STATUSES},
        "overall_pass_accuracy": overall_accuracy,
        "overall_label_accuracy": label_accuracy,
        "vulnerability_detection": vulnerability,
        "reachability": reachability,
        "reachability_excluding_boundary": reachability_excluding_boundary,
        "reachability_engine_boundary_only": reachability_boundary_only,
        "noise_reduction": noise,
        "suspicious_package": suspicious,
        "dependency_disclosure": disclosure,
        "evidence": evidence,
        "execution": execution,
        "per_category": per_category,
        "baseline": payload.get("baseline"),
    }
    (REPORTS / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    failures = []
    for r in results:
        if r["match_status"] in ("FAIL", "PARTIAL", "ERROR", "UNSUPPORTED"):
            failed_checks = [k for k, v in (r.get("checks") or {}).items() if v is False]
            failures.append({
                "case_id": r["case_id"], "category": r["category"],
                "match_status": r["match_status"], "failed_checks": failed_checks,
                "engine_boundary": r.get("engine_boundary"),
                "expected_verdict": r["expected_verdict"], "actual_verdict": r.get("actual_verdict"),
                "exit_code": r["exit_code"], "notes": r.get("notes", []),
                "expected_findings": r.get("expected_findings", []),
                "actual_findings": r.get("actual_findings", []),
                "output_dir": r.get("output_dir"),
            })
    (REPORTS / "failures.json").write_text(json.dumps({"count": len(failures), "failures": failures},
                                                      indent=2) + "\n", encoding="utf-8")

    (REPORTS / "benchmark_report.md").write_text(render(metrics, failures, payload, results), encoding="utf-8")
    print(f"scored {len(results)} cases: {dict(status_counts)}")
    print(f"vulnerability P={vulnerability['precision']} R={vulnerability['recall']} F1={vulnerability['f1']}")
    print(f"reachability P={reachability['precision']} R={reachability['recall']} F1={reachability['f1']}")
    return 0


def fmt(value, pct=False):
    if value is None:
        return "n/a"
    return f"{value:.2%}" if pct else str(value)


def render(metrics: dict, failures: list[dict], payload: dict, results: list[dict]) -> str:
    v, r, n = metrics["vulnerability_detection"], metrics["reachability"], metrics["noise_reduction"]
    s, d, e, x = metrics["suspicious_package"], metrics["dependency_disclosure"], metrics["evidence"], metrics["execution"]
    cat_rows = "\n".join(
        f"| {c} | {p['cases']} | {p['status']['PASS']} | {p['status']['PARTIAL']} | {p['status']['FAIL']} | "
        f"{p['status']['ERROR']} | {p['status']['UNSUPPORTED']} | {fmt(p['pass_accuracy'], True)} |"
        for c, p in metrics["per_category"].items())
    fail_rows = "\n".join(
        f"| {f['case_id']} | {f['match_status']} | {', '.join(f['failed_checks']) or '-'} | "
        f"{'; '.join(f['notes'])[:220]} |" for f in failures if f["match_status"] in ("FAIL", "ERROR", "PARTIAL"))
    baseline = payload.get("baseline") or {}
    boundary_rows = "\n".join(
        f"- **{x['case_id']}** ({x['engine_boundary']}): {x['match_status']}"
        for x in results if x.get("engine_boundary"))
    return f"""# ChainBench-100 Benchmark Report

Corpus: **{metrics['corpus']}** — {metrics['cases_total']} cases, {metrics['cases_evaluated']} evaluated
(the rest are `UNSUPPORTED`: formats the engine does not parse).

Run started `{payload['run_started_utc']}`, finished `{payload['run_finished_utc']}`.
Engine flags: `{' '.join(payload['engine_flags'])}`. LLM disabled. cdxgen disabled.

## Headline

| Measure | Value |
|---|---|
| Status PASS / PARTIAL / FAIL / ERROR / UNSUPPORTED | {metrics['status_counts']['PASS']} / {metrics['status_counts']['PARTIAL']} / {metrics['status_counts']['FAIL']} / {metrics['status_counts']['ERROR']} / {metrics['status_counts']['UNSUPPORTED']} |
| Overall PASS accuracy (of evaluated) | {fmt(metrics['overall_pass_accuracy'], True)} |
| Label accuracy (PASS+PARTIAL, of evaluated) | {fmt(metrics['overall_label_accuracy'], True)} |
| Vulnerability detection precision / recall / F1 | {fmt(v['precision'])} / {fmt(v['recall'])} / {fmt(v['f1'])} (TP {v['tp']}, FP {v['fp']}, FN {v['fn']}) |
| Reachability precision / recall / F1 | {fmt(r['precision'])} / {fmt(r['recall'])} / {fmt(r['f1'])} (TP {r['tp']}, FP {r['fp']}, FN {r['fn']}, TN {r['tn']}) |
| Reachability excluding engine-boundary cases P / R / F1 | {fmt(metrics['reachability_excluding_boundary']['precision'])} / {fmt(metrics['reachability_excluding_boundary']['recall'])} / {fmt(metrics['reachability_excluding_boundary']['f1'])} |
| Java-boundary reachability P / R / F1 | {fmt(metrics['reachability_engine_boundary_only']['precision'])} / {fmt(metrics['reachability_engine_boundary_only']['recall'])} / {fmt(metrics['reachability_engine_boundary_only']['f1'])} |
| Noise reduction (engine actual) | {fmt(n['noise_reduction_percent_actual'])}% ({n['dismissed_actual']} of {n['raw_findings_actual']} dismissed) |
| Noise reduction (ground truth) | {fmt(n['noise_reduction_percent_truth'])}% ({n['raw_findings_truth'] - n['actionable_truth']} of {n['raw_findings_truth']} dismissed) |
| Suspicious-package accuracy / precision / recall | {fmt(s['accuracy'], True)} / {fmt(s['precision'])} / {fmt(s['recall'])} (TP {s['tp']}, FP {s['fp']}, FN {s['fn']}) |
| Dependency-disclosure case accuracy | {fmt(d['case_accuracy'], True)} ({d['cases_correct']}/{d['cases_supported']}) |
| Dependency-disclosure item recall | {fmt(d['item_recall'], True)} ({d['matched_items']}/{d['expected_items']}); unexpected items {d['unexpected_items']} |
| Evidence completeness | {fmt(e['completeness'], True)} ({e['complete']}/{e['items']}) |
| Case execution success | {fmt(x['case_execution_success'], True)} |
| Artifact generation success | {fmt(x['artifact_generation_success'], True)} |
| Exit-code correctness | {fmt(x['exit_code_correctness'], True)} over {x['exit_code_asserted_cases']} asserted cases |
| Scan time avg / median / p95 (s) | {fmt(x['average_scan_seconds'])} / {fmt(x['median_scan_seconds'])} / {fmt(x['p95_scan_seconds'])} |
| Baseline test_project | {baseline.get('status', 'n/a')} (observed {baseline.get('observed', {})}) |

## Per category

| Category | Cases | PASS | PARTIAL | FAIL | ERROR | UNSUPPORTED | PASS accuracy |
|---|---|---|---|---|---|---|---|
{cat_rows}

## Failures and partials

| Case | Status | Failed checks | Notes |
|---|---|---|---|
{fail_rows or '| none | | | |'}

Full detail: [failures.json](failures.json) and [metrics.json](metrics.json).

## Engine boundary cases

{boundary_rows or '- none'}

## Method and limitations

- Ground truth is authored in `tools/corpus_spec.py` from the fixture design and the quoted advisory text. The OSV snapshot supplies only the advisory *set* for each pinned version; registry facts are checked against the spec.
- Vulnerability truth shares its database (OSV) with the engine, so vulnerability-level scores measure the pipeline, not OSV coverage. Reachability, suspicious, and disclosure truth are independent of the engine.
- The engine queries live OSV and public registries. Results depend on that network state at run time; the snapshot records the state used to build the truth. A changed advisory set appears as a vulnerability FP/FN, not as a silent pass.
- Maven Central search is intermittently slow; a lookup that fails is recorded as unknown and not flagged.
"""


if __name__ == "__main__":
    raise SystemExit(main())

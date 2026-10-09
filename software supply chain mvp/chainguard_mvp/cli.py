"""Command-line scanner entry point."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .dashboard import write_dashboard
from .llm import vulnerable_functions
from .osv import query_vulnerabilities
from .parsers import discover_manifests, parse_manifests, parse_manifest, parse_manifests_with_diagnostics
from .reachability import analyze_package
from .sbom import create_sbom
from .slopsquat import inspect_package
from .trace import Tracer
from .vex import write_vex

STAGE_ORDER = ["parse", "sbom", "osv_lookup", "reachability", "slopsquat", "vex_output"]

#: The scanned repository is untrusted: its `.git/config` and `.gitattributes`
#: are attacker-controlled, and git executes commands those files configure
#: (the core.fsmonitor hook, clean/smudge filters, textconv, external diff
#: drivers). These flags keep every git call from running repository code:
#: the fsmonitor hook is disabled, the external diff driver and textconv are
#: disabled, and the diff is taken against the index instead of the worktree so
#: no clean/smudge filter is ever applied. See THREAT_MODEL and ADR-010.
GIT_HARDENING = ("-c", "core.fsmonitor=false", "--no-pager")


def _extract_functions(text: str) -> list[str]:
    """Extract likely callable names from terse advisory phrasing."""
    candidates = re.findall(r"`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)`", text)
    candidates.extend(re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(\)", text))
    candidates.extend(re.findall(r"\b(?:method|function|utility function)\s+`?([A-Za-z_$][\w$]*)", text, flags=re.I))
    candidates.extend(re.findall(r"\bwith\s+(?:the\s+)?([A-Za-z_$][\w$]*)\s+method\b", text, flags=re.I))
    if re.search(r"\b(?:calling|call|invok)\w*\b", text, flags=re.I):
        candidates.extend(f"{module}.{method}" for module, method in
                          re.findall(r"`([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(\)", text))
    if "full_load" in text.lower() and any(term in text.lower() for term in
                                            ("vulnerab", "arbitrary code execution", "susceptible")):
        candidates.extend(["full_load", "yaml.full_load", "yaml.load"])
    if "full_loader" in text.lower():
        candidates.append("FullLoader")
    ignored = {"false", "true", "none", "null", "object", "string", "number", "tmpdir", "or", "and",
               "via", "when", "with", "before", "after", "only", "use", "uses", "method", "function",
               "functions", "loader", "vulnerability", "versions", "version", "standard", "provided",
               "vary", "cookie", "set-cookie", "cache-control", "proxy-authorization", "session"}
    return list(dict.fromkeys(value for value in candidates if value.lower() not in ignored
                              and not value.endswith((".prototype", ".permanent"))))


def _diff_added_packages(root: Path, manifests: list[Path], diff_ref: str) -> list[dict[str, str]]:
    added = []
    repo = root if root.is_dir() else root.parent
    validation = subprocess.run(["git", *GIT_HARDENING, "rev-parse", "--verify", f"{diff_ref}^{{commit}}"],
                                cwd=repo, capture_output=True, text=True, timeout=20)
    if validation.returncode != 0:
        raise ValueError(f"Invalid git ref {diff_ref!r}: {validation.stderr.strip() or 'not found'}")
    for manifest in manifests:
        try:
            relative = manifest.relative_to(repo).as_posix()
        except ValueError:
            relative = manifest.name
        try:
            diff = subprocess.run(["git", *GIT_HARDENING, "diff", "--cached", "--no-ext-diff",
                                   "--no-textconv", "--unified=0", diff_ref, "--", relative],
                                  cwd=repo, capture_output=True, text=True, timeout=20)
            original = subprocess.run(["git", *GIT_HARDENING, "show", f"{diff_ref}:{relative}"],
                                      cwd=repo, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if diff.returncode != 0:
            continue
        old_records = []
        if original.returncode == 0:
            try:
                with tempfile.TemporaryDirectory(prefix="chainguard-diff-") as temp:
                    old_manifest = Path(temp) / manifest.name
                    old_manifest.write_text(original.stdout, encoding="utf-8")
                    old_records = parse_manifest(old_manifest)
            except OSError:
                continue
        elif original.returncode != 0 and original.stderr and "not a valid object name" in original.stderr.lower():
            raise ValueError(f"Invalid git ref {diff_ref!r} while reading {relative}")
        current_records = parse_manifest(manifest)
        old_by_name = {(p["ecosystem"], p["name"].lower()): p for p in old_records}
        added.extend(p for p in current_records
                     if (p["ecosystem"], p["name"].lower()) not in old_by_name
                     or old_by_name[(p["ecosystem"], p["name"].lower())]["version"] != p["version"])
    unique = {(p["ecosystem"], p["name"].lower(), p["version"]): p for p in added}
    return sorted(unique.values(), key=lambda p: (p["ecosystem"], p["name"].lower(), p["version"]))


def _decision(vulnerability: dict[str, Any], root: Path, no_llm: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    package = vulnerability["package"]
    advisory = vulnerability.get("advisory_text", "")
    llm = None if no_llm else vulnerable_functions(advisory)
    llm_functions = list(llm.get("vulnerable_functions", [])) if llm else []
    heuristic_functions = _extract_functions(advisory)
    # The LLM is a hint only (ADR-002, THREAT_MODEL §4.4): it may ADD candidate
    # function names, but it must never remove the deterministic advisory-derived
    # ones. Taking the union keeps a wrong or manipulated LLM answer from
    # suppressing a real vulnerable-function call and turning it into a false
    # not_affected verdict; an empty LLM list falls back to the heuristics.
    functions = list(dict.fromkeys([*heuristic_functions, *llm_functions]))
    function_source = ("llm+advisory_backticks" if llm_functions and heuristic_functions
                       else "llm" if llm_functions else "advisory_backticks")
    reachability = analyze_package(root, package, functions)
    if not reachability["imported"]:
        status, justification = "not_affected", "vulnerable_code_not_present"
        impact, source = "The dependency was not imported or required in scanned source files.", "import-check"
    elif not functions:
        status, justification = "affected", None
        impact, source = "function-level data unavailable", "conservative-default"
    elif not reachability["call_evidence"]:
        status, justification = "not_affected", "vulnerable_code_not_in_execute_path"
        impact, source = "No calls to the advisory's identified vulnerable functions were found.", "llm" if llm_functions else "heuristic"
    else:
        status, justification = "affected", None
        impact, source = "A call to an advisory-identified vulnerable function was found.", "llm" if llm_functions else "heuristic"
    # Confidence is only meaningful for functions the LLM actually contributed.
    confidence = float(llm.get("confidence", 0.0)) if llm_functions else None
    record = {"id": vulnerability["id"], "aliases": vulnerability["aliases"],
              "summary": vulnerability["summary"], "details": vulnerability["details"],
              "severity": vulnerability["severity"], "fixed_version": vulnerability["fixed_version"],
              "package": package, "status": status, "justification": justification,
              "impact_statement": impact, "evidence": {
                  "vulnerable_functions": functions,
                  "function_source": function_source,
                  "confidence": confidence,
                  "import": reachability["import_evidence"], "calls": reachability["call_evidence"]}}
    locations = list(dict.fromkeys(
        f"{item['file']}:{item['line']}" for item in reachability["import_evidence"] + reachability["call_evidence"]))
    chain = {"vuln_id": vulnerability["id"], "aliases": vulnerability["aliases"],
             "package": package["name"], "version": package["version"], "severity": vulnerability["severity"],
             "advisory_functions": functions,
             "called_functions_found": [item["name"] for item in reachability["call_evidence"]],
             "imported": reachability["imported"], "evidence": locations,
             "verdict": status, "justification": justification, "confidence": confidence,
             "decision_source": source}
    return record, chain


def _summary(vulnerabilities: list[dict[str, Any]], decisions: list[dict[str, Any]],
             suspicious: list[dict[str, Any]]) -> dict[str, int | float]:
    dismissed = sum(item["status"] == "not_affected" for item in decisions)
    actionable = sum(item["status"] == "affected" for item in decisions)
    total = len(vulnerabilities)
    return {"total_vulnerabilities": total, "dismissed_unreachable": dismissed,
            "actionable": actionable, "suspicious_packages": sum(item["suspicious"] for item in suspicious),
            "noise_reduced_percent": round((dismissed / total) * 100, 1) if total else 0.0}


def _print_summary(summary: dict[str, int | float]) -> None:
    cyan, green, yellow, reset = "\033[36m", "\033[32m", "\033[33m", "\033[0m"
    print(f"{cyan}ChainGuard MVP scan summary{reset}")
    print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"Dismissed as unreachable: {green}{summary['dismissed_unreachable']}{reset}")
    print(f"Actionable: {yellow}{summary['actionable']}{reset}")
    print(f"Suspicious packages: {yellow}{summary['suspicious_packages']}{reset}")
    print(f"Noise reduced by {summary['noise_reduced_percent']}%")


def run(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2
    scan_root = target if target.is_dir() else target.parent
    started = datetime.now(timezone.utc)
    tracer = Tracer({"tool_version": __version__, "python_version": sys.version.split()[0],
                     "flags": {"no_llm": args.no_llm, "out_dir": str(args.out_dir),
                               "fail_on_actionable": args.fail_on_actionable, "diff": args.diff,
                               "dashboard": args.dashboard},
                     "timestamp": started.isoformat().replace("+00:00", "Z"),
                     "project_path": str(target)})

    with tracer.stage("parse") as stage:
        manifests = discover_manifests(target)
        parsed_packages, unresolved_deps = parse_manifests_with_diagnostics(manifests)
        try:
            packages = _diff_added_packages(scan_root, manifests, args.diff) if args.diff else parsed_packages
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            print(f"error: unable to diff manifests against {args.diff!r}: {error}", file=sys.stderr)
            return 2
        for dep in unresolved_deps:
            spec = dep.get("version_specifier", "*") or "*"
            rel_file = Path(dep.get("file", "")).name if dep.get("file") else "manifest"
            print(f"warning: skipped dependency declaration in {rel_file}: "
                  f"{dep['name']} ({spec}) [{dep.get('reason', 'unresolved')}] — no "
                  f"exact-version analysis performed; see unresolved_dependencies "
                  f"in report.json", file=sys.stderr)
        stage.record(items_in=len(manifests), items_out=len(packages),
                     summary={"manifests": len(manifests), "diff_ref": args.diff,
                              "packages_before_diff": len(parsed_packages),
                              "unresolved_dependencies_count": len(unresolved_deps)},
                     items=packages + unresolved_deps)
    for package in packages:
        tracer.register_package(package)
        tracer.journey_event(package, "parse", "parsed", {"name": package["name"], "version": package["version"]})

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # The trace schema and existing report schemas are intentionally kept
    # separate; OSV items capture both the batch query and returned IDs.
    with tracer.stage("osv_lookup", len(packages)) as stage:
        vulnerabilities = query_vulnerabilities(packages)
        ids_by_purl: dict[str, list[str]] = {}
        for vuln in vulnerabilities:
            ids_by_purl.setdefault(vuln["package"]["purl"], []).append(vuln["id"])
        stage.record(items_out=len(vulnerabilities),
                     summary={"query_status": "completed" if packages else "skipped_empty_inventory",
                              "vulnerability_count": len(vulnerabilities)},
                     items=[{"package": package["name"], "purl": package["purl"],
                             "vulnerability_ids": ids_by_purl.get(package["purl"], [])}
                            for package in packages])
    vulns_by_purl: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulnerabilities:
        package = vuln["package"]
        vulns_by_purl.setdefault(package["purl"], []).append(vuln)
    for package in packages:
        hits = vulns_by_purl.get(package["purl"], [])
        tracer.journey_event(package, "osv_lookup", "vulnerabilities_found" if hits else "none_found",
                             [v["id"] for v in hits])
        if not hits:
            tracer.journey_event(package, "reachability", "skipped_no_vulnerabilities",
                                 "No OSV advisory was returned for this package.")

    with tracer.stage("sbom", len(packages)) as stage:
        sbom_path = out_dir / "sbom.cdx.json"
        sbom = create_sbom(scan_root, packages, sbom_path)
        if sbom.get("specVersion") != "1.5":
            sbom["specVersion"] = "1.5"
            sbom_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
        components = sbom.get("components", [])
        stage.record(items_out=len(components), summary={"format": sbom.get("bomFormat", "n/a"),
                                                        "spec_version": sbom.get("specVersion", "n/a")},
                     items=components)
    for package in packages:
        tracer.journey_event(package, "sbom", "written", package["purl"])

    with tracer.stage("reachability", len(vulnerabilities)) as stage:
        decisions, chains = [], []
        for vuln in vulnerabilities:
            decision, chain = _decision(vuln, scan_root, args.no_llm)
            decisions.append(decision)
            chains.append(chain)
            tracer.add_evidence_chain(chain)
            package = vuln["package"]
            tracer.journey_event(package, "reachability", decision["status"],
                                 {"vuln_id": vuln["id"], "justification": decision["justification"]},
                                 chain["evidence"])
        stage.record(items_out=len(decisions),
                     summary={"affected": sum(d["status"] == "affected" for d in decisions),
                              "not_affected": sum(d["status"] == "not_affected" for d in decisions)},
                     items=[{"vuln_id": d["id"], "package": d["package"]["name"],
                             "status": d["status"], "evidence": d["evidence"]} for d in decisions])

    with tracer.stage("slopsquat", len(packages)) as stage:
        suspicious = [inspect_package(package, no_llm=args.no_llm) for package in packages]
        stage.record(items_out=sum(item["suspicious"] for item in suspicious),
                     summary={"suspicious": sum(item["suspicious"] for item in suspicious),
                              "registry_unavailable": sum(bool(item.get("lookup_error")) for item in suspicious)},
                     items=suspicious)
    for item in suspicious:
        package = item["package"]
        tracer.journey_event(package, "slopsquat", item["status"], item["reasons"] or item.get("lookup_error") or "no risk flags")

    with tracer.stage("vex_output", len(decisions)) as stage:
        vex = write_vex(decisions, out_dir / "openvex.json")
        stage.record(items_out=len(vex.get("statements", [])),
                     summary={"statements": len(vex.get("statements", [])), "path": str(out_dir / "openvex.json")},
                     items=vex.get("statements", []))
    for package in packages:
        tracer.journey_event(package, "vex_output", "written", package["purl"])

    summary = _summary(vulnerabilities, decisions, suspicious)
    report = {"schema_version": 1, "target": str(target), "diff_ref": args.diff,
              "packages": packages, "vulnerabilities": decisions, "suspicious_packages": suspicious,
              "summary": summary}
    if unresolved_deps:
        report["unresolved_dependencies"] = unresolved_deps
    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    tracer.stages.sort(key=lambda item: STAGE_ORDER.index(item["stage"]))
    tracer.totals = {**summary, "vulnerability_total_check":
                     summary["dismissed_unreachable"] + summary["actionable"] == summary["total_vulnerabilities"]}
    trace = tracer.write(out_dir / "trace.json")
    if args.dashboard:
        run_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        write_dashboard(trace, report, sbom, vex, str(target), run_time, out_dir / "dashboard.html")

    _print_summary(summary)
    if args.fail_on_actionable and (summary["actionable"] or summary["suspicious_packages"]):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chainguard_mvp", description="Reachability-aware dependency risk scanner")
    parser.add_argument("path", help="project directory or supported manifest")
    parser.add_argument("--no-llm", action="store_true", help="disable optional configured LLM calls")
    parser.add_argument("--out-dir", default="./out", help="directory for SBOM, VEX, and report artifacts")
    parser.add_argument("--fail-on-actionable", action="store_true", help="exit 1 when actionable or suspicious findings exist")
    parser.add_argument("--diff", metavar="GIT_REF", help="check only dependencies added since the git ref")
    parser.add_argument("--dashboard", action="store_true", help="write a self-contained HTML dashboard")
    return parser


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())

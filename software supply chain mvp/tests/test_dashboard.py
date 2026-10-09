import json
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


class DashboardParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.json_script_ids = []
        self.external_resources = []
        self.scripts = []
        self._script = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self._script = {"attrs": attrs, "text": []}
            if attrs.get("type") == "application/json":
                self.json_script_ids.append(attrs.get("id"))
        for name in ("src", "href"):
            if attrs.get(name, "").startswith(("http://", "https://")):
                self.external_resources.append(attrs[name])

    def handle_data(self, data):
        if self._script is not None:
            self._script["text"].append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._script is not None:
            self.scripts.append(self._script)
            self._script = None


def run_cli(target, out_dir, *flags):
    return subprocess.run(
        [sys.executable, "-m", "chainguard_mvp.cli", str(target), "--no-llm",
         "--out-dir", str(out_dir), *flags],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )


@pytest.mark.integration
def test_trace_and_dashboard_integration(tmp_path):
    output = tmp_path / "out"
    result = run_cli(ROOT / "test_project", output, "--dashboard")
    assert result.returncode == 0, result.stderr

    trace = json.loads((output / "trace.json").read_text(encoding="utf-8"))
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert trace["schema_version"] == 1
    required = {"parse", "sbom", "osv_lookup", "reachability", "slopsquat", "vex_output"}
    assert {stage["stage"] for stage in trace["stages"]} == required
    assert all({"items_in", "items_out"} <= stage.keys() for stage in trace["stages"])
    totals = trace["totals"]
    assert totals["dismissed_unreachable"] + totals["actionable"] == totals["total_vulnerabilities"]
    assert report["summary"]["dismissed_unreachable"] + report["summary"]["actionable"] == report["summary"]["total_vulnerabilities"]
    assert totals["total_vulnerabilities"] == report["summary"]["total_vulnerabilities"]
    assert len(trace["evidence_chains"]) == len(report["vulnerabilities"])
    assert set(report) == {"schema_version", "target", "diff_ref", "packages", "vulnerabilities",
                           "suspicious_packages", "summary"}
    sbom = json.loads((output / "sbom.cdx.json").read_text(encoding="utf-8"))
    vex = json.loads((output / "openvex.json").read_text(encoding="utf-8"))
    assert set(sbom) >= {"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies"}
    assert set(vex) == {"@context", "@id", "author", "timestamp", "version", "statements"}

    parser = DashboardParser()
    dashboard = (output / "dashboard.html").read_text(encoding="utf-8")
    parser.feed(dashboard)
    parser.close()
    assert set(parser.json_script_ids) >= {"trace-data", "report-data", "sbom-data", "vex-data"}
    assert not parser.external_resources
    external_load = __import__("re").compile(r"(?:src|href)=[\"']https?://", __import__("re").I)
    assert not external_load.search(dashboard)
    assert not __import__("re").search(r"@import\s+url\(['\"]?https?://", dashboard, __import__("re").I)
    assert "fetch(" not in dashboard
    assert "XMLHttpRequest" not in dashboard
    assert str(report["summary"]["total_vulnerabilities"]) in dashboard
    assert str(report["summary"]["actionable"]) in dashboard
    for script in parser.scripts:
        if script["attrs"].get("type") == "application/json":
            json.loads("".join(script["text"]))


@pytest.mark.integration
def test_dashboard_empty_project(tmp_path):
    project, output = tmp_path / "empty", tmp_path / "empty-out"
    project.mkdir()
    result = run_cli(project, output, "--dashboard")
    assert result.returncode == 0, result.stderr
    trace = json.loads((output / "trace.json").read_text(encoding="utf-8"))
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["total_vulnerabilities"] == 0
    assert not report["suspicious_packages"]
    assert trace["totals"]["total_vulnerabilities"] == 0
    assert (output / "dashboard.html").is_file()
    parser = DashboardParser()
    parser.feed((output / "dashboard.html").read_text(encoding="utf-8"))
    parser.close()
    assert not parser.external_resources


def test_embedded_json_escapes_script_terminators():
    from chainguard_mvp.dashboard import _embedded

    rendered = _embedded("report-data", {"text": "closing </script><script>alert(1)</script>"})
    assert "</script><script>alert(1)" not in rendered
    parser = DashboardParser()
    parser.feed(rendered)
    parser.close()
    import re
    match = re.search(r"<script type=\"application/json\" id=\"report-data\">(.*?)</script>", rendered)
    assert match
    # HTML parsing treats the embedded text as literal script data; decode the
    # escaped slash using the JSON's valid escaped character sequence.
    json.loads(match.group(1).replace("<\\/script", "</script"))


def test_existing_report_structure_is_not_extended():
    expected = {"schema_version", "target", "diff_ref", "packages", "vulnerabilities",
                "suspicious_packages", "summary"}
    sample_report = {"schema_version": 1, "target": ".", "diff_ref": None, "packages": [],
                     "vulnerabilities": [], "suspicious_packages": [],
                     "summary": {"total_vulnerabilities": 0, "dismissed_unreachable": 0,
                                 "actionable": 0, "suspicious_packages": 0, "noise_reduced_percent": 0}}
    assert set(sample_report) == expected
    from chainguard_mvp.cli import _summary
    assert set(_summary([], [], [])) == {"total_vulnerabilities", "dismissed_unreachable", "actionable",
                                         "suspicious_packages", "noise_reduced_percent"}

import json
import tempfile
import unittest
from pathlib import Path

from chainguard_mvp.cli import _extract_functions
from chainguard_mvp.parsers import parse_manifest
from chainguard_mvp.reachability import analyze_package
from chainguard_mvp.slopsquat import edit_distance
from chainguard_mvp.vex import build_vex


class CoreTests(unittest.TestCase):
    def test_requirements_parser_ignores_flags_and_comments(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text("# comment\nrequests==2.31.0\n-r other.txt\nflask>=2\n", encoding="utf-8")
            records = parse_manifest(path)
        self.assertEqual([record["name"] for record in records], ["requests"])
        self.assertEqual(records[0]["purl"], "pkg:pypi/requests@2.31.0")

    def test_package_json_strips_range_prefixes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "package.json"
            path.write_text(json.dumps({"dependencies": {"lodash": "^4.17.15"},
                                       "devDependencies": {"vitest": "~1.0.0"}}), encoding="utf-8")
            records = parse_manifest(path)
        self.assertEqual({record["version"] for record in records}, {"4.17.15", "1.0.0"})

    def test_python_reachability_distinguishes_call(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.py"
            path.write_text("import yaml\nyaml.safe_load(data)\n", encoding="utf-8")
            package = {"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI",
                       "purl": "pkg:pypi/pyyaml@5.3"}
            safe = analyze_package(temp, package, ["yaml.load"])
            unsafe = analyze_package(temp, package, ["safe_load"])
        self.assertTrue(safe["imported"])
        self.assertEqual(safe["status"], "not_affected")
        self.assertEqual(unsafe["status"], "affected")
        self.assertEqual(unsafe["call_evidence"][0]["line"], 2)

    def test_function_match_respects_qualified_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.py"
            path.write_text("import requests\nrequests.get(url)\n", encoding="utf-8")
            package = {"name": "requests", "version": "1", "ecosystem": "PyPI", "purl": "pkg:pypi/requests@1"}
            unrelated = analyze_package(temp, package, ["Session"])
            matching = analyze_package(temp, package, ["requests.get"])
        self.assertEqual(unrelated["call_evidence"], [])
        self.assertEqual(len(matching["call_evidence"]), 1)

    def test_advisory_fallback_identifies_unsafe_pyyaml_functions(self):
        advisory = ("A vulnerability in PyYAML can cause arbitrary code execution when "
                    "input is processed through the full_load method or FullLoader.")
        functions = _extract_functions(advisory)
        self.assertIn("yaml.load", functions)
        self.assertIn("yaml.full_load", functions)

    def test_edit_distance_and_openvex_justification(self):
        self.assertEqual(edit_distance("flask", "flsak"), 2)
        decision = {"id": "GHSA-test", "package": {"purl": "pkg:pypi/foo@1"},
                    "status": "not_affected", "justification": "vulnerable_code_not_present"}
        vex = build_vex([decision])
        self.assertEqual(vex["version"], 1)
        self.assertEqual(vex["statements"][0]["justification"], "vulnerable_code_not_present")

    def test_unpinned_and_ranged_requirements_diagnostics(self):
        from chainguard_mvp.parsers import parse_manifest_with_diagnostics
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requirements.txt"
            path.write_text(
                "package==1.2.3\n"
                "package>=1.2\n"
                "package~=1.2\n"
                "package\n"
                "malformed requirement\n",
                encoding="utf-8",
            )
            pinned, unresolved = parse_manifest_with_diagnostics(path)

        self.assertEqual(len(pinned), 1)
        self.assertEqual(pinned[0]["name"], "package")
        self.assertEqual(pinned[0]["version"], "1.2.3")

        self.assertEqual(len(unresolved), 4)
        reasons = [u["reason"] for u in unresolved]
        specs = [u["version_specifier"] for u in unresolved]
        names = [u["name"] for u in unresolved]

        self.assertIn("unpinned_or_ranged_requirement", reasons)
        self.assertIn("malformed_requirement", reasons)
        self.assertIn(">=1.2", specs)
        self.assertIn("~=1.2", specs)
        self.assertIn("*", specs)
        self.assertIn("package", names)

    def test_sbom_cdxgen_version_is_pinned_and_configurable(self):
        import os
        from unittest.mock import patch
        from chainguard_mvp.sbom import create_sbom, PINNED_CDXGEN_PACKAGE

        with tempfile.TemporaryDirectory() as temp:
            out_file = Path(temp) / "sbom.cdx.json"
            packages = [{"name": "demo", "version": "1.0", "ecosystem": "PyPI", "purl": "pkg:pypi/demo@1.0"}]

            # 1. Test pinned command construction
            with patch("shutil.which", return_value="/bin/npx"), patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 1
                create_sbom(temp, packages, out_file)

                self.assertTrue(mock_run.called)
                cmd = mock_run.call_args[0][0]
                self.assertNotIn("@cyclonedx/cdxgen", cmd)  # Must NOT be unpinned
                self.assertIn(PINNED_CDXGEN_PACKAGE, cmd)  # Must be explicitly pinned

            # 2. Test disable flag
            with patch.dict(os.environ, {"CHAINGUARD_DISABLE_CDXGEN": "1"}), patch("subprocess.run") as mock_run:
                data = create_sbom(temp, packages, out_file)
                self.assertFalse(mock_run.called)
                self.assertEqual(data["bomFormat"], "CycloneDX")
                self.assertEqual(data["specVersion"], "1.5")


if __name__ == "__main__":
    unittest.main()


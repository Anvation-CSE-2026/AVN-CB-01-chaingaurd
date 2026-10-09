"""ChainBench-100 case specification.

Every expectation in this file is authored from the fixture design and from the
advisory text quoted in ADVISORY_FUNCTIONS. ChainGuard output is never used to
choose an expected answer. The build step (build_corpus.py) only derives the
advisory *set* for each pinned version from the OSV snapshot, and it checks the
registry facts recorded in the snapshot against the ghost/control annotations
below.

Field meanings
--------------
pins          analysed concrete versions: (ecosystem, name, version)
imports       packages the application code imports (independent truth)
calls         {package: [function names called from entry-reachable code]}
dead_calls    {package: [function names called only from dead/unused code]}
ghost         pinned names that must NOT exist on their public registry
disclosures   [(name, [acceptable reason codes])] that must be disclosed
supported     False when the format is outside the engine's parser set
engine_boundary  a stated capability boundary the case deliberately probes
"""
from __future__ import annotations

import json

P, N, M = "PyPI", "npm", "Maven"

# Disclosure reason vocabulary. The first three are engine-implemented codes.
UNP = "unpinned_or_ranged_requirement"
MAL = "malformed_requirement"
NCV = "non_concrete_version"
UMP = "unresolved_maven_property"
MIS = "missing_version"
# Benchmark-specified expectations the engine does not yet implement.
IDX = "index_override_option"
PRX = "ranged_declaration_proxied"
MLM = "manifest_lockfile_mismatch"
DNL = "declared_not_in_lockfile"

#: Function-level truth, curated by reading each advisory's text. An advisory
#: absent from this table has no function-level data (conservative policy).
ADVISORY_FUNCTIONS = {
    # PyYAML: "susceptible to arbitrary code execution ... through the full_load
    # method or with the FullLoader loader" (yaml.load defaults to FullLoader in 5.x)
    "GHSA-6757-jp84-gxfx": ["yaml.full_load", "yaml.load"],
    "PYSEC-2020-96": ["yaml.full_load", "yaml.load"],
    "GHSA-8q59-q68h-6hv4": ["yaml.full_load", "yaml.load"],
    "PYSEC-2021-142": ["yaml.full_load", "yaml.load"],
    # lodash 4.17.15 / 4.17.21
    "GHSA-29mw-wpgm-hmr9": ["toNumber", "trim", "trimEnd"],
    "GHSA-35jh-r3h4-6jhm": ["template"],  # "via the template function"
    "GHSA-r5fr-rjxr-66jc": ["template"],  # "_.template imports key names"
    "GHSA-f23m-r3pf-42rh": ["unset", "omit"],  # "_.unset and _.omit"
    "GHSA-xxjr-mmjv-4gpg": ["unset", "omit"],  # "_.unset and _.omit"
    "GHSA-p6mc-m468-83gw": ["pick", "set", "setWith", "update", "updateWith", "zipObjectDeep"],
    # Guava 31.1-jre (Java: the engine never analyses .java sources)
    "GHSA-7g45-4rm6-3mm3": ["FileBackedOutputStream"],
    "GHSA-5mg8-w23w-74h3": ["createTempDir"],
    # minimist 1.2.0: the vulnerable entry point is the parser itself
    "GHSA-vh95-rmgr-6w4m": ["minimist"],
}


def pj(deps=None, dev=None):
    data = {"name": "bench-app", "version": "1.0.0", "private": True}
    if deps is not None:
        data["dependencies"] = deps
    if dev is not None:
        data["devDependencies"] = dev
    return json.dumps(data, indent=2) + "\n"


def poetry(pairs):
    return "\n".join('[[package]]\nname = "%s"\nversion = "%s"\n' % (n, v) for n, v in pairs)


def pom(deps):
    body = ""
    for group, artifact, version in deps:
        tag = "" if version is None else f"\n      <version>{version}</version>"
        body += (f"    <dependency>\n      <groupId>{group}</groupId>\n"
                 f"      <artifactId>{artifact}</artifactId>{tag}\n    </dependency>\n")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <modelVersion>4.0.0</modelVersion>\n  <groupId>bench</groupId>\n"
            "  <artifactId>bench-app</artifactId>\n  <version>1.0.0</version>\n"
            f"  <dependencies>\n{body}  </dependencies>\n</project>\n")


JAVA_APP = "package app;\n\npublic class App {}\n"
JAVA_FBOS = ("package app;\n\nimport com.google.common.io.FileBackedOutputStream;\n\n"
             "public class App {\n  public static FileBackedOutputStream open() {\n"
             "    return new FileBackedOutputStream(1024);\n  }\n}\n")
JAVA_TEMP = ("package app;\n\nimport com.google.common.io.Files;\n\n"
             "public class App {\n  public static Object dir() throws Exception {\n"
             "    return Files.createTempDir();\n  }\n}\n")
GUAVA = ("com.google.guava", "guava")
LODASH_JS = {"package.json": pj({"lodash": "4.17.15"})}


def case(cid, cat, desc, files, *, pins=(), imports=(), calls=None, dead=None, ghost=(),
         disclosures=(), supported=True, engine_boundary=None, assert_reach=True,
         assert_verdict=True, rationale="", path=""):
    return {
        "case_id": cid, "category": cat, "description": desc, "files": files,
        "pins": [list(p) for p in pins], "imports": list(imports),
        "calls": calls or {}, "dead_calls": dead or {}, "ghost": list(ghost),
        "disclosures": [[name, list(reasons)] for name, reasons in disclosures],
        "supported": supported, "engine_boundary": engine_boundary,
        "assert_reachability": assert_reach, "assert_verdict": assert_verdict,
        "rationale": rationale, "call_path": path,
    }


PYYAML_APP = ("import yaml\n\n\ndef main(text):\n    return yaml.full_load(text)\n\n\n"
              "if __name__ == '__main__':\n    print(main('a: 1'))\n")

CASES = []
add = CASES.append

# ---------------------------------------------------------------- CLEAN (11)
add(case("CB-CLEAN-001", "clean", "Exact pin of patched PyYAML 6.0.1 used via safe_load.",
         {"requirements.txt": "pyyaml==6.0.1\n",
          "src/app.py": "import yaml\n\n\ndef parse(text):\n    return yaml.safe_load(text)\n"},
         pins=[(P, "pyyaml", "6.0.1")], imports=["pyyaml"], calls={"pyyaml": ["yaml.safe_load"]},
         rationale="OSV lists zero advisories for pyyaml 6.0.1; the call is not vulnerable."))
add(case("CB-CLEAN-002", "clean", "Two exact pins with zero advisories (six, click).",
         {"requirements.txt": "six==1.16.0\nclick==8.1.7\n",
          "src/cli.py": "import click\nimport six\n\n\n@click.command()\ndef main():\n"
                        "    print(six.PY3)\n\n\nif __name__ == '__main__':\n    main()\n"},
         pins=[(P, "six", "1.16.0"), (P, "click", "8.1.7")], imports=["six", "click"],
         rationale="Both pinned versions have zero OSV advisories."))
add(case("CB-CLEAN-003", "clean", "npm exact pins with zero advisories (is-number, chalk).",
         {"package.json": pj({"is-number": "7.0.0", "chalk": "5.3.0"}),
          "index.js": "const chalk = require('chalk');\nconsole.log(chalk.green('ok'));\n"},
         pins=[(N, "is-number", "7.0.0"), (N, "chalk", "5.3.0")], imports=["chalk"],
         rationale="Zero OSV advisories for both pinned versions."))
add(case("CB-CLEAN-004", "clean", "Maven guava 33.3.1-jre, patched and unaffected.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "33.3.1-jre")]),
          "src/main/java/app/App.java": "package app;\n\nimport com.google.common.collect.ImmutableList;\n\n"
                                        "public class App {\n  public static Object v() {\n"
                                        "    return ImmutableList.of(1, 2);\n  }\n}\n"},
         pins=[(M, "com.google.guava:guava", "33.3.1-jre")],
         imports=["com.google.guava:guava"], rationale="Zero OSV advisories for guava 33.3.1-jre."))
add(case("CB-CLEAN-005", "clean", "Manifest with only comments; nothing to analyse.",
         {"requirements.txt": "# no runtime dependencies yet\n\n",
          "src/main.py": "def main():\n    return 0\n"},
         rationale="No declarations exist, so the correct result is an empty, clean inventory."))
add(case("CB-CLEAN-006", "clean", "package.json with empty dependency sections.",
         {"package.json": pj({}, {}), "index.js": "module.exports = () => 1;\n"},
         rationale="Empty sections must not produce findings or disclosures."))
add(case("CB-CLEAN-007", "clean", "Vulnerable lodash vendored under node_modules must be skipped.",
         {"package.json": pj({"is-number": "7.0.0"}),
          "index.js": "const isNumber = require('is-number');\nconsole.log(isNumber(7));\n",
          "node_modules/lodash/package.json": '{"name": "lodash", "version": "4.17.15"}\n'},
         pins=[(N, "is-number", "7.0.0")], imports=["is-number"],
         rationale="node_modules is dependency output, not the project's declared inventory."))
add(case("CB-CLEAN-008", "clean", "Vulnerable requests in venv/ must be skipped by discovery.",
         {"requirements.txt": "pyyaml==6.0.1\n",
          "src/app.py": "import yaml\n\nprint(yaml.safe_load('a: 1'))\n",
          "venv/requirements.txt": "requests==2.19.0\n"},
         pins=[(P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         rationale="venv/ is an environment directory, not a project manifest."))
add(case("CB-CLEAN-009", "clean", "Exact pin with spaces around == and an inline comment.",
         {"requirements.txt": "pyyaml == 6.0.1  # pinned for CI\n",
          "src/app.py": "import yaml\n\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         rationale="Whitespace and comments around an exact pin must still parse as a pin."))
add(case("CB-CLEAN-010", "clean", "Clean inventory across PyPI, npm and Maven together.",
         {"requirements.txt": "six==1.16.0\n",
          "package.json": pj({"chalk": "5.3.0"}),
          "pom.xml": pom([(GUAVA[0], GUAVA[1], "33.3.1-jre")]),
          "src/app.py": "import six\nprint(six.PY3)\n", "index.js": "require('chalk');\n"},
         pins=[(P, "six", "1.16.0"), (N, "chalk", "5.3.0"), (M, "com.google.guava:guava", "33.3.1-jre")],
         imports=["six", "chalk"], rationale="Three ecosystems, all unaffected."))
add(case("CB-CLEAN-011", "clean", "Environment marker after an exact pin.",
         {"requirements.txt": "click==8.1.7; python_version >= '3.8'\n",
          "src/app.py": "import click\n\n\n@click.command()\ndef main():\n    pass\n"},
         pins=[(P, "click", "8.1.7")], imports=["click"],
         rationale="The marker must not corrupt the pinned version."))

# --------------------------------------------------------- VULNERABLE (11)
# Vulnerability detection only: reachability and verdict are not asserted.
VULN_KW = dict(assert_reach=False, assert_verdict=False)
add(case("CB-VULN-001", "vulnerable", "requests 2.19.0 declared but never imported.",
         {"requirements.txt": "requests==2.19.0\n", "src/app.py": "def main():\n    return 1\n"},
         pins=[(P, "requests", "2.19.0")], rationale="Detection of a declared vulnerable pin.",
         **VULN_KW))
add(case("CB-VULN-002", "vulnerable", "requests 2.19.0 declared and imported (no function data).",
         {"requirements.txt": "requests==2.19.0\n",
          "src/app.py": "import requests\n\n\ndef fetch(url):\n    return requests.get(url, timeout=5)\n"},
         pins=[(P, "requests", "2.19.0")], imports=["requests"],
         rationale="Detection with an imported package whose advisories carry no function data.",
         **VULN_KW))
add(case("CB-VULN-003", "vulnerable", "requests 2.19.0 present only in poetry.lock.",
         {"poetry.lock": poetry([("requests", "2.19.0")]), "src/app.py": "print('no imports')\n"},
         pins=[(P, "requests", "2.19.0")], rationale="Lockfile-only resolution must be analysed.",
         **VULN_KW))
add(case("CB-VULN-004", "vulnerable", "PyYAML 5.3 declared only.",
         {"requirements.txt": "pyyaml==5.3\n", "src/app.py": "print('x')\n"},
         pins=[(P, "pyyaml", "5.3")], rationale="Four advisories for PyYAML 5.3.", **VULN_KW))
add(case("CB-VULN-005", "vulnerable", "Flask 0.12 declared only (many advisories).",
         {"requirements.txt": "Flask==0.12\n", "app.py": "print('x')\n"},
         pins=[(P, "flask", "0.12")], rationale="Multi-advisory detection under a capitalised name.",
         **VULN_KW))
add(case("CB-VULN-006", "vulnerable", "lodash 4.17.15 declared only.",
         {"package.json": pj({"lodash": "4.17.15"}), "index.js": "console.log(1);\n"},
         pins=[(N, "lodash", "4.17.15")], rationale="Six advisories for lodash 4.17.15.", **VULN_KW))
add(case("CB-VULN-007", "vulnerable", "lodash 4.17.21 still carries three advisories.",
         {"package.json": pj({"lodash": "4.17.21"}), "index.js": "console.log(1);\n"},
         pins=[(N, "lodash", "4.17.21")],
         rationale="Upgrade to the minimum patched release does not clear every advisory.",
         **VULN_KW))
add(case("CB-VULN-008", "vulnerable", "minimist 1.2.0 declared only.",
         {"package.json": pj({"minimist": "1.2.0"}), "index.js": "console.log(1);\n"},
         pins=[(N, "minimist", "1.2.0")], rationale="Two advisories for minimist 1.2.0.",
         **VULN_KW))
add(case("CB-VULN-009", "vulnerable", "Guava 31.1-jre declared in pom.xml only.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "31.1-jre")]), "src/main/java/app/App.java": JAVA_APP},
         pins=[(M, "com.google.guava:guava", "31.1-jre")], rationale="Two Maven advisories.",
         **VULN_KW))
add(case("CB-VULN-010", "vulnerable", "requests 2.32.4 declared and not patched to the latest.",
         {"requirements.txt": "requests==2.32.4\n", "src/app.py": "print('x')\n"},
         pins=[(P, "requests", "2.32.4")], rationale="Four advisories for requests 2.32.4.",
         **VULN_KW))
add(case("CB-VULN-011", "vulnerable", "Vulnerable pins in nested manifests across two ecosystems.",
         {"services/api/requirements.txt": "pyyaml==5.3\n", "services/api/app.py": "print('x')\n",
          "web/package.json": pj({"lodash": "4.17.15"}), "web/index.js": "console.log(1);\n"},
         pins=[(P, "pyyaml", "5.3"), (N, "lodash", "4.17.15")],
         rationale="Nested discovery must find manifests below the root.", **VULN_KW))

# ------------------------------------------------------------ REACHABLE (13)
add(case("CB-REACH-001", "reachable", "Direct yaml.full_load call in the entry module.",
         {"requirements.txt": "pyyaml==5.3\n", "src/app.py": PYYAML_APP},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         path="src/app.py:main -> yaml.full_load",
         rationale="Direct call of an advisory-named vulnerable function from the entry point."))
add(case("CB-REACH-002", "reachable", "from yaml import full_load, then called by alias.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "from yaml import full_load\n\n\ndef load_doc(text):\n    return full_load(text)\n\n\n"
                        "print(load_doc('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         path="src/app.py:load_doc -> full_load (alias of yaml.full_load)",
         rationale="Reachability must survive an import alias."))
add(case("CB-REACH-003", "reachable", "yaml.load() with the default (FullLoader) in PyYAML 5.x.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\nprint(yaml.load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.load"]},
         path="src/app.py -> yaml.load (default FullLoader)",
         rationale="yaml.load without a Loader uses FullLoader in 5.x, which the advisory covers."))
add(case("CB-REACH-004", "reachable", "Cross-module call: main -> config -> yaml.full_load.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/main.py": "from config import load_config\n\nprint(load_config('a: 1'))\n",
          "src/config.py": "import yaml\n\n\ndef load_config(text):\n    return yaml.full_load(text)\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         path="src/main.py -> src/config.py:load_config -> yaml.full_load",
         rationale="Reachability across modules must be found."))
add(case("CB-REACH-005", "reachable", "Class method reached via instance: Parser().parse -> yaml.full_load.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/loaders.py": "import yaml\n\n\nclass Parser:\n    def parse(self, text):\n"
                            "        return yaml.full_load(text)\n",
          "src/app.py": "from loaders import Parser\n\nprint(Parser().parse('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         path="src/app.py -> Parser.parse -> yaml.full_load",
         rationale="Call through a method of an application class."))
add(case("CB-REACH-006", "reachable", "Function passed by reference to map() and invoked.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\n\ndef load_all(docs):\n    return list(map(yaml.full_load, docs))\n\n\n"
                        "print(load_all(['a: 1']))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         path="src/app.py:load_all -> map(yaml.full_load) invokes the function",
         rationale="A reference that is executed is reachable; an AST call-only check misses it."))
add(case("CB-REACH-007", "reachable", "Call inside an if __name__ == '__main__' guard.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\nif __name__ == '__main__':\n    print(yaml.full_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         path="src/app.py (__main__ block) -> yaml.full_load",
         rationale="Module-level entry code must count as reachable."))
add(case("CB-REACH-008", "reachable", "lodash _.template reached from index.js via server.js.",
         {"package.json": pj({"lodash": "4.17.15"}),
          "index.js": "const render = require('./server');\nconsole.log(render('<%= a %>', { a: 1 }));\n",
          "server.js": "const _ = require('lodash');\n\nmodule.exports = function render(tpl, data) {\n"
                       "  return _.template(tpl)(data);\n};\n"},
         pins=[(N, "lodash", "4.17.15")], imports=["lodash"], calls={"lodash": ["template"]},
         path="index.js -> server.js:render -> _.template",
         rationale="GHSA-35jh 'via the template function' is reached; the engine's extractor is expected to miss it."))
add(case("CB-REACH-009", "reachable", "ESM named import of template and direct call.",
         {"package.json": pj({"lodash": "4.17.15"}),
          "index.js": "import { template } from 'lodash';\n\nconsole.log(template('<%= a %>')({ a: 1 }));\n"},
         pins=[(N, "lodash", "4.17.15")], imports=["lodash"], calls={"lodash": ["template"]},
         path="index.js -> template (ESM named import of lodash)",
         rationale="Named-import call of the vulnerable template function."))
add(case("CB-REACH-010", "reachable", "_.omit reached: unset/omit advisories reachable, template not.",
         {"package.json": pj({"lodash": "4.17.15"}),
          "index.js": "const _ = require('lodash');\n\nconsole.log(_.omit({ a: 1, b: 2 }, ['b']));\n"},
         pins=[(N, "lodash", "4.17.15")], imports=["lodash"], calls={"lodash": ["omit"]},
         path="index.js -> _.omit",
         rationale="Mixed per-advisory truth inside one package: only unset/omit advisories are reachable."))
add(case("CB-REACH-011", "reachable", "minimist(argv) called directly from the entry script.",
         {"package.json": pj({"minimist": "1.2.0"}),
          "index.js": "const minimist = require('minimist');\n\nconsole.log(minimist(process.argv.slice(2)));\n"},
         pins=[(N, "minimist", "1.2.0")], imports=["minimist"], calls={"minimist": ["minimist"]},
         path="index.js -> minimist(process.argv)",
         rationale="GHSA-vh95 is reachable; the second advisory has no function data (conservative)."))
add(case("CB-REACH-012", "reachable", "Guava FileBackedOutputStream constructed in Java source.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "31.1-jre")]),
          "src/main/java/app/App.java": JAVA_FBOS},
         pins=[(M, "com.google.guava:guava", "31.1-jre")], imports=["com.google.guava:guava"],
         calls={"com.google.guava:guava": ["FileBackedOutputStream"]},
         path="src/main/java/app/App.java:open -> FileBackedOutputStream",
         engine_boundary="java_source_reachability",
         rationale="Ground truth is reachable. The engine does not parse .java, so this probes a stated boundary."))
add(case("CB-REACH-013", "reachable", "Guava Files.createTempDir() called from Java source.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "31.1-jre")]),
          "src/main/java/app/App.java": JAVA_TEMP},
         pins=[(M, "com.google.guava:guava", "31.1-jre")], imports=["com.google.guava:guava"],
         calls={"com.google.guava:guava": ["createTempDir"]},
         path="src/main/java/app/App.java:dir -> Files.createTempDir",
         engine_boundary="java_source_reachability",
         rationale="Ground truth is reachable. Java reachability is outside the engine's analysis."))

# ----------------------------------------------------------- UNREACHABLE (13)
add(case("CB-UNREACH-001", "unreachable", "PyYAML 5.3 declared, never imported.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import json\n\nprint(json.dumps({'a': 1}))\n"},
         pins=[(P, "pyyaml", "5.3")], rationale="Vulnerable package absent from application code."))
add(case("CB-UNREACH-002", "unreachable", "PyYAML imported, only yaml.safe_load called.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="Imported, but the vulnerable functions are not called."))
add(case("CB-UNREACH-003", "unreachable", "json.load (control) plus yaml.dump; no vulnerable call.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import json\nimport yaml\n\n\ndef read(path):\n    with open(path) as fh:\n"
                        "        return json.load(fh)\n\n\nprint(yaml.dump({'a': 1}))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="A 'load' name on another module must not be attributed to yaml."))
add(case("CB-UNREACH-004", "unreachable", "full_load appears only in a comment and a docstring.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\n# Do not call yaml.full_load on untrusted input.\n"
                        "\"\"\"Docstring mentions yaml.full_load for context only.\"\"\"\n\n\n"
                        "def parse(text):\n    return yaml.safe_load(text)\n\n\nprint(parse('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="Text mentions are not calls; an AST-based check must ignore them."))
add(case("CB-UNREACH-005", "unreachable", "A different object's full_load() method is called.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\n\nclass Parser:\n    def full_load(self, text):\n"
                        "        return text.strip()\n\n\nprint(Parser().full_load(' a: 1 '))\n"
                        "print(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="Same method name on an unrelated class is not the PyYAML function."))
add(case("CB-UNREACH-006", "unreachable", "yaml.full_load only in a dead function never invoked.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\n\ndef main():\n    return yaml.safe_load('a: 1')\n\n\n"
                        "def legacy_loader(text):\n    return yaml.full_load(text)\n\n\nprint(main())\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], dead={"pyyaml": ["yaml.full_load"]},
         rationale="Call exists in source but is not reachable from the entry point."))
add(case("CB-UNREACH-007", "unreachable", "yaml.full_load only under a statically false branch.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\nif False:\n    print(yaml.full_load('a: 1'))\n"
                        "print(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"], dead={"pyyaml": ["yaml.full_load"]},
         rationale="A statically dead branch is not an execute path."))
add(case("CB-UNREACH-008", "unreachable", "Alias to safe_load; full_load never referenced.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "from yaml import safe_load as load\n\nprint(load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="Alias resolution must not map a safe call to the vulnerable function."))
add(case("CB-UNREACH-009", "unreachable", "yaml.dump only.",
         {"requirements.txt": "pyyaml==5.3\n",
          "src/app.py": "import yaml\n\nprint(yaml.dump({'a': 1}))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="Imported module whose only used function is not in any advisory."))
add(case("CB-UNREACH-010", "unreachable", "lodash/debounce imported; no vulnerable function used.",
         {"package.json": pj({"lodash": "4.17.15"}),
          "index.js": "const debounce = require('lodash/debounce');\n\nconsole.log(typeof debounce);\n"},
         pins=[(N, "lodash", "4.17.15")], imports=["lodash"],
         rationale="Subpath import of a package; none of the six advisories' functions are called."))
add(case("CB-UNREACH-011", "unreachable", "_.template named only in a JS comment.",
         {"package.json": pj({"lodash": "4.17.15"}),
          "index.js": "const _ = require('lodash');\n\n// Never pass user input to _.template(userInput) here.\n"
                      "console.log(_.map([1, 2], (x) => x * 2));\n"},
         pins=[(N, "lodash", "4.17.15")], imports=["lodash"],
         rationale="A regex-based call check over comments produces a false reachability."))
add(case("CB-UNREACH-012", "unreachable", "minimist imported but never called.",
         {"package.json": pj({"minimist": "1.2.0"}),
          "index.js": "const minimist = require('minimist');\n\nvoid minimist;\nmodule.exports = { ok: true };\n"},
         pins=[(N, "minimist", "1.2.0")], imports=["minimist"],
         rationale="Reference without invocation is not a call."))
add(case("CB-UNREACH-013", "unreachable", "Guava declared; Java app does not import it.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "31.1-jre")]),
          "src/main/java/app/App.java": "package app;\n\nimport java.util.List;\n\npublic class App {\n"
                                        "  static List<String> names() { return List.of(\"a\"); }\n}\n"},
         pins=[(M, "com.google.guava:guava", "31.1-jre")],
         rationale="Declared but not used by the application (no Java-import analysis is needed here)."))

# ------------------------------------------------------------ SUSPICIOUS (8)
add(case("CB-SUSP-001", "suspicious", "Ghost PyPI name pinned in requirements.txt.",
         {"requirements.txt": "pandas-fastload-turbo==1.0.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "pandas-fastload-turbo", "1.0.0")], ghost=["pandas-fastload-turbo"],
         rationale="Name does not exist on PyPI (HTTP 404 in the snapshot)."))
add(case("CB-SUSP-002", "suspicious", "Ghost PyPI name alongside a legitimate pin.",
         {"requirements.txt": "pyrequests-secure-kit==2.1.0\nsix==1.16.0\n",
          "src/app.py": "import six\nprint(six.PY3)\n"},
         pins=[(P, "pyrequests-secure-kit", "2.1.0"), (P, "six", "1.16.0")], imports=["six"],
         ghost=["pyrequests-secure-kit"], rationale="Ghost is flagged; the legitimate pin is not."))
add(case("CB-SUSP-003", "suspicious", "Ghost PyPI name with a click pin.",
         {"requirements.txt": "fastapi-autoconf-pro==0.3.1\nclick==8.1.7\n",
          "src/app.py": "import click\n\n\n@click.command()\ndef main():\n    pass\n"},
         pins=[(P, "fastapi-autoconf-pro", "0.3.1"), (P, "click", "8.1.7")], imports=["click"],
         ghost=["fastapi-autoconf-pro"], rationale="Hallucinated-style package name."))
add(case("CB-SUSP-004", "suspicious", "Ghost npm name with a patched chalk pin.",
         {"package.json": pj({"react-hooks-utility-kit-pro": "1.0.0", "chalk": "5.3.0"}),
          "index.js": "require('chalk');\n"},
         pins=[(N, "react-hooks-utility-kit-pro", "1.0.0"), (N, "chalk", "5.3.0")], imports=["chalk"],
         ghost=["react-hooks-utility-kit-pro"], rationale="npm registry returns 404 for the name."))
add(case("CB-SUSP-005", "suspicious", "Ghost npm name with is-number.",
         {"package.json": pj({"express-router-autoload-x": "2.0.0", "is-number": "7.0.0"}),
          "index.js": "require('is-number');\n"},
         pins=[(N, "express-router-autoload-x", "2.0.0"), (N, "is-number", "7.0.0")],
         imports=["is-number"], ghost=["express-router-autoload-x"],
         rationale="Non-existent unscoped npm package."))
add(case("CB-SUSP-006", "suspicious", "Ghost scoped npm package.",
         {"package.json": pj({"@acme-internal/auth-core": "3.2.1", "is-number": "7.0.0"}),
          "index.js": "console.log(1);\n"},
         pins=[(N, "@acme-internal/auth-core", "3.2.1"), (N, "is-number", "7.0.0")],
         ghost=["@acme-internal/auth-core"], rationale="Scoped name absent from the public npm registry."))
add(case("CB-SUSP-007", "suspicious", "Ghost Maven artifact next to guava 33.3.1-jre.",
         {"pom.xml": pom([("com.chainbench.fictional", "widget-core", "1.0.0"),
                          (GUAVA[0], GUAVA[1], "33.3.1-jre")]),
          "src/main/java/app/App.java": JAVA_APP},
         pins=[(M, "com.chainbench.fictional:widget-core", "1.0.0"),
               (M, "com.google.guava:guava", "33.3.1-jre")],
         ghost=["com.chainbench.fictional:widget-core"],
         rationale="Maven Central search returns zero artifacts for the coordinate."))
add(case("CB-SUSP-008", "suspicious", "Ghost PyPI name with a patched PyYAML.",
         {"requirements.txt": "numpy-accel-fastmath==0.9.2\npyyaml==6.0.1\n",
          "src/app.py": "import yaml\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "numpy-accel-fastmath", "0.9.2"), (P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         ghost=["numpy-accel-fastmath"], rationale="Ghost plus a clean legitimate dependency."))

# ---------------------------------------------------------- SLOPSQUATTING (10)
add(case("CB-SLOP-001", "slopsquatting", "Typo of requests (reqeusts) in requirements.txt.",
         {"requirements.txt": "reqeusts==2.31.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "reqeusts", "2.31.0")], ghost=["reqeusts"],
         rationale="Transposed-letter typosquat of a popular package; absent on PyPI."))
add(case("CB-SLOP-002", "slopsquatting", "Typo of pyyaml (pyyamll).",
         {"requirements.txt": "pyyamll==6.0.1\n", "src/app.py": "print('x')\n"},
         pins=[(P, "pyyamll", "6.0.1")], ghost=["pyyamll"],
         rationale="Doubled-letter typosquat; absent on PyPI."))
add(case("CB-SLOP-003", "slopsquatting", "Typo of flask (flaskk).",
         {"requirements.txt": "flaskk==2.3.2\n", "src/app.py": "print('x')\n"},
         pins=[(P, "flaskk", "2.3.2")], ghost=["flaskk"], rationale="Doubled-letter typosquat."))
add(case("CB-SLOP-004", "slopsquatting", "Typo of numpy (numpyy).",
         {"requirements.txt": "numpyy==1.26.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "numpyy", "1.26.0")], ghost=["numpyy"], rationale="Doubled-letter typosquat."))
add(case("CB-SLOP-005", "slopsquatting", "Typo of urllib3 (urlib3x).",
         {"requirements.txt": "urlib3x==2.0.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "urlib3x", "2.0.0")], ghost=["urlib3x"], rationale="Dropped letter plus suffix."))
add(case("CB-SLOP-006", "slopsquatting", "Hallucinated npm helper (axios-retry-helpers-plus).",
         {"package.json": pj({"axios-retry-helpers-plus": "1.0.0"}), "index.js": "console.log(1);\n"},
         pins=[(N, "axios-retry-helpers-plus", "1.0.0")], ghost=["axios-retry-helpers-plus"],
         rationale="Plausible-sounding helper that does not exist on npm."))
add(case("CB-SLOP-007", "slopsquatting", "Typo of beautifulsoup4 (beautifulsoup5).",
         {"requirements.txt": "beautifulsoup5==1.0.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "beautifulsoup5", "1.0.0")], ghost=["beautifulsoup5"],
         rationale="Version-number suffix squat; absent on PyPI."))
add(case("CB-SLOP-008", "slopsquatting", "Hallucinated PyPI name with an -x suffix.",
         {"requirements.txt": "sqlalchemy-fastpool-x==1.0.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "sqlalchemy-fastpool-x", "1.0.0")], ghost=["sqlalchemy-fastpool-x"],
         rationale="Plausible combination of two real project names."))
add(case("CB-SLOP-009", "slopsquatting", "CONTROL: boto is near boto3 but established on PyPI.",
         {"requirements.txt": "boto==2.49.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "boto", "2.49.0")],
         rationale="Name similarity alone must not flag an established package with many releases."))
add(case("CB-SLOP-010", "slopsquatting", "CONTROL: lodash-es is close to lodash but established on npm.",
         {"package.json": pj({"lodash-es": "4.17.21"}), "index.js": "console.log(1);\n"},
         pins=[(N, "lodash-es", "4.17.21")],
         rationale="Established near-name control; the registry record is not suspicious."))

# ------------------------------------------------------ DEPENDENCY_CONFUSION (7)
add(case("CB-DC-001", "dependency_confusion", "Internal name plus --extra-index-url override.",
         {"requirements.txt": ("--extra-index-url https://pypi.internal.example.invalid/simple\n"
                               "acme-internal-auth==1.4.0\n"),
          "src/app.py": "print('x')\n"},
         pins=[(P, "acme-internal-auth", "1.4.0")], ghost=["acme-internal-auth"],
         disclosures=[("--extra-index-url", [IDX])],
         rationale="Index override is the classic confusion precondition; it must be disclosed."))
add(case("CB-DC-002", "dependency_confusion", "Internal name with a plain --index-url override.",
         {"requirements.txt": ("--index-url https://pypi.internal.example.invalid/simple\n"
                               "acme-core-utils==2.0.1\n"),
          "src/app.py": "print('x')\n"},
         pins=[(P, "acme-core-utils", "2.0.1")], ghost=["acme-core-utils"],
         disclosures=[("--index-url", [IDX])],
         rationale="Primary index replaced; disclose the override and flag the unresolved name."))
add(case("CB-DC-003", "dependency_confusion", "Scoped internal npm name absent from the public registry.",
         {"package.json": pj({"@acme-corp/payments-core": "1.0.0", "is-number": "7.0.0"}),
          "index.js": "require('is-number');\n"},
         pins=[(N, "@acme-corp/payments-core", "1.0.0"), (N, "is-number", "7.0.0")],
         imports=["is-number"], ghost=["@acme-corp/payments-core"],
         rationale="Private-scope name that an attacker could publish publicly."))
add(case("CB-DC-004", "dependency_confusion", "Internal Maven coordinate absent from Maven Central.",
         {"pom.xml": pom([("com.acme.internal", "auth-core", "1.0.0")]),
          "src/main/java/app/App.java": JAVA_APP},
         pins=[(M, "com.acme.internal:auth-core", "1.0.0")],
         ghost=["com.acme.internal:auth-core"],
         rationale="Internal groupId with no public artifact."))
add(case("CB-DC-005", "dependency_confusion", "CONTROL: established public name, no index override.",
         {"requirements.txt": "requests-toolbelt==1.0.0\n",
          "src/app.py": "import requests_toolbelt\n"},
         pins=[(P, "requests-toolbelt", "1.0.0")], imports=["requests-toolbelt"],
         rationale="An established public package is not a confusion precondition by itself."))
add(case("CB-DC-006", "dependency_confusion", "Index override in front of an established package.",
         {"requirements.txt": ("--extra-index-url https://pypi.internal.example.invalid/simple\n"
                               "pyyaml==6.0.1\n"),
          "src/app.py": "import yaml\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         disclosures=[("--extra-index-url", [IDX])],
         rationale="The override alone is a disclosable condition even when the package is public."))
add(case("CB-DC-007", "dependency_confusion", "Internal-looking npm name chalk-internal-logger.",
         {"package.json": pj({"chalk-internal-logger": "2.0.0"}), "index.js": "console.log(1);\n"},
         pins=[(N, "chalk-internal-logger", "2.0.0")], ghost=["chalk-internal-logger"],
         rationale="Name resembles a real package family but is absent from npm."))

# ------------------------------------------------------------- UNPINNED (12)
add(case("CB-UNPIN-001", "unpinned", "Lower-bound range requests>=2.19.0.",
         {"requirements.txt": "requests>=2.19.0\n", "src/app.py": "print('x')\n"},
         disclosures=[("requests", [UNP])], rationale="Ranged declaration must be disclosed."))
add(case("CB-UNPIN-002", "unpinned", "Bare name with no version (flask).",
         {"requirements.txt": "flask\n", "src/app.py": "print('x')\n"},
         disclosures=[("flask", [UNP])], rationale="No version at all is unresolvable."))
add(case("CB-UNPIN-003", "unpinned", "Wildcard pin requests==2.*.",
         {"requirements.txt": "requests==2.*\n", "src/app.py": "print('x')\n"},
         disclosures=[("requests", [MAL, UNP])], rationale="A wildcard is not an exact version."))
add(case("CB-UNPIN-004", "unpinned", "Compatible-release range pyyaml~=5.3.",
         {"requirements.txt": "pyyaml~=5.3\n", "src/app.py": "print('x')\n"},
         disclosures=[("pyyaml", [UNP])], rationale="Compatible-release operator is a range."))
add(case("CB-UNPIN-005", "unpinned", "CONTROL: arbitrary-equality pin requests===2.19.0 is exact.",
         {"requirements.txt": "requests===2.19.0\n", "src/app.py": "print('x')\n"},
         pins=[(P, "requests", "2.19.0")],
         rationale="=== is an exact pin and must be analysed, not disclosed as ranged."))
add(case("CB-UNPIN-006", "unpinned", "npm caret range ^4.17.15 analysed as its lower bound.",
         {"package.json": pj({"lodash": "^4.17.15"}), "index.js": "console.log(1);\n"},
         pins=[(N, "lodash", "4.17.15")], disclosures=[("lodash", [PRX])],
         rationale="The lower bound is analysed, but the range itself is silently dropped. It must be disclosed."))
add(case("CB-UNPIN-007", "unpinned", "npm tilde range ~1.2.0 analysed as its lower bound.",
         {"package.json": pj({"minimist": "~1.2.0"}), "index.js": "console.log(1);\n"},
         pins=[(N, "minimist", "1.2.0")], disclosures=[("minimist", [PRX])],
         rationale="Same silent lower-bound proxy as the caret case."))
add(case("CB-UNPIN-008", "unpinned", "npm 'latest' dist-tag.",
         {"package.json": pj({"is-number": "latest"}), "index.js": "console.log(1);\n"},
         disclosures=[("is-number", [NCV])], rationale="A dist-tag is not a version."))
add(case("CB-UNPIN-009", "unpinned", "npm wildcard '*' and '>=' range.",
         {"package.json": pj({"chalk": "*", "uuid": ">=9.0.0"}), "index.js": "console.log(1);\n"},
         disclosures=[("chalk", [NCV]), ("uuid", [NCV])], rationale="Wildcard and comparator ranges."))
add(case("CB-UNPIN-010", "unpinned", "Maven version is an unresolved property.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "${guava.version}")]),
          "src/main/java/app/App.java": JAVA_APP},
         disclosures=[("com.google.guava:guava", [UMP])],
         rationale="Property placeholders cannot be resolved without a parent POM."))
add(case("CB-UNPIN-011", "unpinned", "Maven dependency with no version element.",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], None)]), "src/main/java/app/App.java": JAVA_APP},
         disclosures=[("com.google.guava:guava", [MIS])],
         rationale="Version may come from dependencyManagement; it must still be disclosed."))
add(case("CB-UNPIN-012", "unpinned", "Space-separated 'requests 2.19.0' (malformed).",
         {"requirements.txt": "requests 2.19.0\n", "src/app.py": "print('x')\n"},
         disclosures=[("requests", [MAL, UNP])], rationale="Malformed requirement line."))

# ------------------------------------------------------ LOCKFILE_MISMATCH (8)
add(case("CB-LOCK-001", "lockfile_mismatch", "requirements pins 2.19.0; poetry.lock resolves 2.32.4.",
         {"requirements.txt": "requests==2.19.0\n", "poetry.lock": poetry([("requests", "2.32.4")]),
          "src/app.py": "print('x')\n"},
         pins=[(P, "requests", "2.19.0"), (P, "requests", "2.32.4")],
         disclosures=[("requests", [MLM])],
         rationale="Two versions of one package disagree; the disagreement must be disclosed."))
add(case("CB-LOCK-002", "lockfile_mismatch", "poetry.lock only (lockfile-only resolution).",
         {"poetry.lock": poetry([("pyyaml", "5.3")]), "src/app.py": "print('x')\n"},
         pins=[(P, "pyyaml", "5.3")],
         rationale="A vulnerable lock entry with no manifest must still be analysed."))
add(case("CB-LOCK-003", "lockfile_mismatch", "requirements pins 6.0.1; poetry.lock resolves 5.3.",
         {"requirements.txt": "pyyaml==6.0.1\n", "poetry.lock": poetry([("pyyaml", "5.3")]),
          "src/app.py": "print('x')\n"},
         pins=[(P, "pyyaml", "6.0.1"), (P, "pyyaml", "5.3")],
         disclosures=[("pyyaml", [MLM])],
         rationale="Manifest says clean, lock says vulnerable; both must surface and the mismatch be disclosed."))
add(case("CB-LOCK-004", "lockfile_mismatch", "flask pinned in requirements, absent from poetry.lock.",
         {"requirements.txt": "flask==0.12\n", "poetry.lock": poetry([("requests", "2.32.4")]),
          "src/app.py": "print('x')\n"},
         pins=[(P, "flask", "0.12"), (P, "requests", "2.32.4")],
         disclosures=[("flask", [DNL])],
         rationale="A declared dependency that the lock does not resolve is a disclosable inconsistency."))
add(case("CB-LOCK-005", "lockfile_mismatch", "Range in requirements satisfied by a 2.19.0 lock entry.",
         {"requirements.txt": "requests>=2.19\n", "poetry.lock": poetry([("requests", "2.19.0")]),
          "src/app.py": "print('x')\n"},
         pins=[(P, "requests", "2.19.0")], disclosures=[("requests", [UNP])],
         rationale="The lock pin is analysed; the range itself is still disclosed."))
add(case("CB-LOCK-006", "lockfile_mismatch", "Lock entry with an empty version string.",
         {"poetry.lock": '[[package]]\nname = "pyyaml"\nversion = ""\n', "src/app.py": "print('x')\n"},
         disclosures=[("pyyaml", [NCV])], rationale="An empty lock version cannot be analysed."))
add(case("CB-LOCK-007", "lockfile_mismatch", "Flask 0.12 pinned; lock resolves flask 2.3.3 (case differs).",
         {"requirements.txt": "Flask==0.12\n", "poetry.lock": poetry([("flask", "2.3.3")]),
          "src/app.py": "print('x')\n"},
         pins=[(P, "Flask", "0.12"), (P, "flask", "2.3.3")],
         disclosures=[("Flask", [MLM])],
         rationale="Different versions under a case-insensitive name must be treated as a mismatch."))
add(case("CB-LOCK-008", "lockfile_mismatch", "CONTROL: same version under different name spelling.",
         {"requirements.txt": "pyyaml==5.3\n", "poetry.lock": poetry([("PyYAML", "5.3")]),
          "src/app.py": "import yaml\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3")], imports=["pyyaml"],
         rationale="Agreeing manifest and lock must not be reported as a mismatch."))

# ------------------------------------------------------------- MIXED (8)
add(case("CB-MIX-001", "mixed", "Actionable + unreachable + ghost + unpinned in one Python repo.",
         {"requirements.txt": ("requests==2.19.0\npyyaml==5.3\nflask==0.12\n"
                               "reqeusts==0.1.0\nsix>=1.0\n"),
          "src/app.py": ("import requests\nimport yaml\n\n\ndef main(text):\n"
                         "    session = requests.Session()\n    return session, yaml.full_load(text)\n\n\n"
                         "print(main('a: 1'))\n")},
         pins=[(P, "requests", "2.19.0"), (P, "pyyaml", "5.3"), (P, "flask", "0.12"),
               (P, "reqeusts", "0.1.0")],
         imports=["requests", "pyyaml"], calls={"pyyaml": ["yaml.full_load"]},
         ghost=["reqeusts"], disclosures=[("six", [UNP])],
         rationale="Each condition is present and must be reported independently."))
add(case("CB-MIX-002", "mixed", "JS: reachable template, dismissed minimist, ghost, caret proxy.",
         {"package.json": pj({"lodash": "4.17.15", "minimist": "1.2.0",
                              "lodash-fast-utils-core": "1.0.0", "uuid": "^9.0.1"}),
          "index.js": "const _ = require('lodash');\n\nconsole.log(_.template('<%= a %>')({ a: 1 }));\n"},
         pins=[(N, "lodash", "4.17.15"), (N, "minimist", "1.2.0"),
               (N, "lodash-fast-utils-core", "1.0.0"), (N, "uuid", "9.0.1")],
         imports=["lodash"], calls={"lodash": ["template"]},
         ghost=["lodash-fast-utils-core"], disclosures=[("uuid", [PRX])],
         rationale="Combines a reachable call the engine should not miss with independent conditions."))
add(case("CB-MIX-003", "mixed", "Reachable full_load plus a manifest/lock version mismatch.",
         {"requirements.txt": "pyyaml==5.3\n", "poetry.lock": poetry([("pyyaml", "6.0.1")]),
          "src/app.py": "import yaml\n\n\ndef load(text):\n    return yaml.full_load(text)\n\n\n"
                        "print(load('a: 1'))\n"},
         pins=[(P, "pyyaml", "5.3"), (P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         calls={"pyyaml": ["yaml.full_load"]}, disclosures=[("pyyaml", [MLM])],
         rationale="Reachable vulnerability and a lockfile disagreement at once."))
add(case("CB-MIX-004", "mixed", "Index override, ghost, and a dead-code call in one project.",
         {"requirements.txt": ("--extra-index-url https://pypi.internal.example.invalid/simple\n"
                               "acme-internal-auth==1.4.0\npyyaml==5.3\n"),
          "src/app.py": ("import yaml\n\n\ndef legacy_loader(text):\n"
                         "    return yaml.full_load(text)\n\n\nprint(yaml.safe_load('a: 1'))\n")},
         pins=[(P, "acme-internal-auth", "1.4.0"), (P, "pyyaml", "5.3")],
         imports=["pyyaml"], dead={"pyyaml": ["yaml.full_load"]},
         ghost=["acme-internal-auth"], disclosures=[("--extra-index-url", [IDX])],
         rationale="Dead-code call must not be actionable; the ghost and the override are separate findings."))
add(case("CB-MIX-005", "mixed", "Ghost typo plus clean pin plus ranged dependency.",
         {"requirements.txt": "pyyamll==0.1.0\npyyaml==6.0.1\nsix>=1.0\n",
          "src/app.py": "import yaml\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyamll", "0.1.0"), (P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         ghost=["pyyamll"], disclosures=[("six", [UNP])],
         rationale="Suspicious-only verdict with an unpinned disclosure."))
add(case("CB-MIX-006", "mixed", "Java reachable guava + ghost + unresolved property (boundary).",
         {"pom.xml": pom([(GUAVA[0], GUAVA[1], "31.1-jre"),
                          ("org.chainbench.fictional", "http-core", "1.0.0"),
                          ("com.fasterxml.jackson.core", "jackson-databind", "${jackson.version}")]),
          "src/main/java/app/App.java": JAVA_FBOS},
         pins=[(M, "com.google.guava:guava", "31.1-jre"),
               (M, "org.chainbench.fictional:http-core", "1.0.0")],
         imports=["com.google.guava:guava"],
         calls={"com.google.guava:guava": ["FileBackedOutputStream"]},
         ghost=["org.chainbench.fictional:http-core"],
         disclosures=[("com.fasterxml.jackson.core:jackson-databind", [UMP])],
         engine_boundary="java_source_reachability",
         rationale="Java reachability is a stated engine boundary; the other conditions are native."))
add(case("CB-MIX-007", "mixed", "Dead template call and reachable omit in one lodash project.",
         {"package.json": pj({"lodash": "4.17.15"}),
          "index.js": ("const _ = require('lodash');\n\nfunction legacy() {\n"
                       "  return _.template('<%= a %>');\n}\n\n"
                       "console.log(_.omit({ a: 1 }, ['a']));\n")},
         pins=[(N, "lodash", "4.17.15")], imports=["lodash"],
         calls={"lodash": ["omit"]}, dead={"lodash": ["template"]},
         rationale="Per-advisory truth: omit-based advisories reachable; template only in dead code."))
add(case("CB-MIX-008", "mixed", "Discovery trap: venv, node_modules, clean pin and unpinned line.",
         {"requirements.txt": "pyyaml==6.0.1\npillow\n",
          "venv/requirements.txt": "pyyaml==5.3\n",
          "node_modules/lodash/package.json": '{"name": "lodash", "version": "4.17.15"}\n',
          "src/app.py": "import yaml\nprint(yaml.safe_load('a: 1'))\n"},
         pins=[(P, "pyyaml", "6.0.1")], imports=["pyyaml"],
         disclosures=[("pillow", [UNP])],
         rationale="Skipped directories must not contribute findings while the real unpinned line is disclosed."))

# ----------------------------------------------------------- UNSUPPORTED (6)
UNSUP_KW = dict(supported=False, assert_reach=False, assert_verdict=False)
add(case("CB-UNSUP-001", "unsupported", "PEP 621 pyproject.toml declaring a vulnerable requests.",
         {"pyproject.toml": ('[project]\nname = "bench"\nversion = "1.0.0"\n'
                             'dependencies = ["requests==2.19.0"]\n'),
          "src/app.py": "import requests\nprint(requests.__name__)\n"},
         pins=[(P, "requests", "2.19.0")], imports=["requests"],
         rationale="pyproject.toml is not a parsed manifest; the vulnerable pin is invisible to the engine.",
         **UNSUP_KW))
add(case("CB-UNSUP-002", "unsupported", "package-lock.json as the only npm inventory.",
         {"package-lock.json": ('{"name": "bench", "lockfileVersion": 3, "packages": '
                                '{"node_modules/lodash": {"version": "4.17.15"}}}\n'),
          "index.js": "console.log(1);\n"},
         pins=[(N, "lodash", "4.17.15")],
         rationale="package-lock.json is not in the supported set; the engine sees nothing.",
         **UNSUP_KW))
add(case("CB-UNSUP-003", "unsupported", "Rust Cargo.toml (crates.io) with a pinned crate.",
         {"Cargo.toml": '[package]\nname = "bench"\nversion = "0.1.0"\n\n[dependencies]\ntime = "=0.1.43"\n',
          "src/main.rs": "fn main() {}\n"},
         rationale="No Cargo parser exists; vulnerability truth is not measured for this ecosystem.",
         **UNSUP_KW))
add(case("CB-UNSUP-004", "unsupported", "Go module (go.mod) with a pinned websocket.",
         {"go.mod": ("module bench\n\ngo 1.21\n\n"
                     "require github.com/gorilla/websocket v1.4.0\n"),
          "main.go": "package main\n\nfunc main() {}\n"},
         rationale="No go.mod parser; not measured.", **UNSUP_KW))
add(case("CB-UNSUP-005", "unsupported", "Ruby Gemfile.lock with rails 5.0.0.",
         {"Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (5.0.0)\n",
          "app.rb": "puts 1\n"},
         rationale="No RubyGems parser; not measured.", **UNSUP_KW))
add(case("CB-UNSUP-006", "unsupported", "Pipenv Pipfile.lock with requests 2.19.0.",
         {"Pipfile.lock": json.dumps({"_meta": {}, "default": {"requests": {"version": "==2.19.0"}}}),
          "src/app.py": "import requests\n"},
         pins=[(P, "requests", "2.19.0")], imports=["requests"],
         rationale="Pipfile.lock is not parsed, so the pinned vulnerable version is missed.",
         **UNSUP_KW))

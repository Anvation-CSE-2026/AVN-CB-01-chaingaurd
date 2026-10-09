# ChainGuard MVP

A small Python 3.11 dependency scanner that combines a CycloneDX SBOM,
OSV advisories, source reachability evidence, and package-name risk checks.
The goal is to separate potentially reachable findings from dependencies that
are absent from the scanned execution paths—not to replace a full SCA platform.

## Install

```sh
python -m pip install .
# Or run from a source checkout:
python -m pip install requests
```

Only `requests` is required at runtime. Python 3.11+ is needed for the standard
library `tomllib` parser.

## Usage

```sh
python -m chainguard_mvp.cli ./test_project
python -m chainguard_mvp.cli ./repo --no-llm --out-dir ./out
python -m chainguard_mvp.cli ./repo --diff origin/main --fail-on-actionable
```

The scanner writes `sbom.cdx.json`, `openvex.json`, and `report.json` into the
output directory. Exit status is nonzero for a missing target, or (when
`--fail-on-actionable` is set) if any vulnerability remains actionable or a
package is suspicious. OSV and registry outages degrade to partial results;
they are recorded in the report when registry checks are unavailable.

Supported manifests are pinned `requirements.txt` entries, Poetry
`[[package]]` entries, `package.json` dependencies and devDependencies, and
Maven `pom.xml` dependencies. Traversal skips `node_modules`, `.git`, virtual
environments, and Python bytecode directories. `--diff REF` compares the
supported manifests against `REF` and analyzes new package/version records.

## How reachability works

For each OSV vulnerability the scanner:

1. Checks whether source imports/requires the affected package. If absent,
   OpenVEX marks it `not_affected` with `vulnerable_code_not_present`.
2. Finds vulnerable function names from an optional configured LLM, or falls
   back to identifiers in backticks and `function()` references in advisory
   text. Python is inspected with `ast`; JavaScript/TypeScript uses regex.
3. If imported but none of the identified vulnerable functions appear called,
   it marks the finding `not_affected` with
   `vulnerable_code_not_in_execute_path`. A call is considered actionable.
   If no function-level clue is available, an imported package remains
   `affected` rather than being optimistically dismissed.

Evidence records source paths, lines, imports, and candidate calls in
`report.json`. The demo imports `requests` and PyYAML, calls `yaml.safe_load`,
and intentionally does not call `yaml.load`.

## Optional LLM

An OpenAI-compatible chat-completions endpoint can be configured using
`CHAINGUARD_LLM_ENDPOINT`, `CHAINGUARD_LLM_API_KEY`, and optionally
`CHAINGUARD_LLM_MODEL`. No LLM is contacted unless both endpoint and key are
present. `--no-llm` disables it. Responses are treated as hints and parsed
strictly as JSON; outages fall back to deterministic heuristics. An answer can
only **add** candidate function names — the advisory-derived set is unioned
with it and never replaced, so a wrong or manipulated answer cannot dismiss a
real call site.

## GitHub Action

This repository includes a composite action in `action.yml` and a pull-request
example workflow in `.github/workflows/example.yml`. The action uploads `out/`
and fails if actionable or suspicious findings remain.

## Limitations

- The parser intentionally handles a constrained subset. Requirements ranges,
  environment markers, workspace protocols, Maven properties/parents, and
  generated lockfile semantics are not fully resolved — but every declaration
  it cannot resolve to one exact version is disclosed as an *unresolved
  dependency* (`unresolved_dependencies` in `report.json`, the `parse` trace
  stage and a stderr warning) instead of being dropped, so a scan can never
  look clean because part of the inventory vanished.
- OSV query results depend on public network availability. Timeouts/retries
  reduce transient failures but cannot guarantee complete coverage.
- The fallback SBOM is a valid minimal CycloneDX 1.5 inventory, not a complete
  dependency graph. If `node` and `npx` exist, cdxgen is attempted with a
  120-second timeout; the npm package is version-pinned
  (`@cyclonedx/cdxgen@10.9.0`) so an unpinned download is never executed,
  `CHAINGUARD_DISABLE_CDXGEN=1` skips it, and it may require network access.
  The pinned package is fetched at scan time without integrity verification —
  a residual supply-chain surface for the scanner itself.
- Reachability is static, best effort, and not data-flow analysis. Regex-based
  JS/TS matching can produce false positives; dynamic imports, aliases,
  reflection, wrappers, and native code may be missed.
- Advisory function extraction can miss vulnerable APIs or infer a name that
  does not represent an exploitable path. A finding is not proof of exploitability.
- Package age and typo checks are heuristics based on a small popularity list.
  New legitimate packages can be flagged; an unavailable registry lookup is
  reported as unknown rather than suspicious.
- This MVP does not verify package signatures, malware, license compliance, or
  transitive dependency resolution comprehensively. Review results before
  making security decisions.

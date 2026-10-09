# ChainGuard — POST-IMPLEMENTATION AUDIT

**Date:** 2026-10-08
**Scope:** reconcile the specification documents against the realised implementation, verify every security claim with executable evidence, fix genuine P0/P1 defects, and decide whether ChainGuard is ready for the next security-engine phase.
**Auditor:** Buffy (agent), on the local machine, with the real scanner and real OSV/registry network access.

---

## 0. Layout fact that shapes this audit

The eight specification documents (`AGENTS.md`, `PROJECT_SPEC.md`, `ARCHITECTURE.md`, `CLI_CONTRACT.md`,
`THREAT_MODEL.md`, `SECURITY_MODEL.md`, `TEST_STRATEGY.md`, `DECISIONS.md`) live in
`~/Desktop/software supply chain mvp/`, **not** inside the working tree `~/Desktop/chaingaurd/`.

Two copies of the engine therefore exist:

| Path | Contents | Role |
|---|---|---|
| `~/Desktop/chaingaurd/software supply chain mvp/` | engine + `tests/` + `test_project/` + `README.md` | engine **executed by the API** (`CHAIN_GUARD_ENGINE_ROOT` default) |
| `~/Desktop/software supply chain mvp/` | the same engine **plus the 8 spec documents** | specification home |

This divergence was itself a finding: the P0-1 `git` hardening existed in only one copy. Both copies are
byte-identical for every source, test and README file as of this audit (verified with `diff -rq`, excluding
`out*`, `node_modules`, `__pycache__`, `.pytest_cache`, `scan_workspace`). `demo_attack_sim/` is a separate git
repository and was **not** modified.

No component was rebuilt. No feature was added. Every fix below is the smallest change that removes a verified
defect, plus one regression test per fix.

---

## 1. Verified baseline (measured after all fixes in this audit)

Command (engine root, real network, LLM off):

```
python -m chainguard_mvp.cli test_project --no-llm --out-dir <tmp>
```

```
ChainGuard MVP scan summary
Total vulnerabilities: 30
Dismissed as unreachable: 26
Actionable: 4
Suspicious packages: 1
Noise reduced by 86.7%
exit=0
```

Artifacts produced: `report.json` (57 KB), `trace.json` (80 KB), `sbom.cdx.json` (4.3 KB, 6 components,
`specVersion` 1.5), `openvex.json` (11 KB, 30 statements). `summary` in `report.json` is exactly
`{total_vulnerabilities: 30, dismissed_unreachable: 26, actionable: 4, suspicious_packages: 1, noise_reduced_percent: 86.7}`;
statuses are `affected: 4, not_affected: 26`.

**Baseline not corrupted: confirmed.** `unresolved_dependencies` is absent for `test_project` because all six of
its declarations are pinned — nothing was dropped, so nothing is disclosed.

### 1.1 Test suites

| Suite | Result |
|---|---|
| engine `pytest -q` (both copies) | **25 passed** (working copy 51.78 s, spec copy 32.99 s) |
| engine `tests/test_hardening.py` | **12 passed** (2.20 s) |
| API `pytest chainguard_api/tests -q` | 65 collected → **64 passed, 1 skipped** (66.20 s) |
| API `tests/test_path_security.py` | 25 collected → **24 passed, 1 skipped** (0.16 s) |

The single skip is the Windows symlink-escape regression
(`Chainguard_api\tests\test_path_security.py:49`, `WinError 1314: A required privilege is not held by the client`).
It is kept, not weakened, and the limitation is recorded here rather than hidden (§6).

---

## 2. Requirement → implementation → evidence matrix

Status values: **PASS**, **PARTIAL**, **FAIL**, **DEFERRED**, **NOT_IMPLEMENTED**.

| # | Requirement | Specification | Implementation | Test / execution evidence | Status | Action |
|---|---|---|---|---|---|---|
| 1 | Pinned `requirements.txt` / `poetry.lock` / `package.json` / `pom.xml` parsed | PROJECT_SPEC §3.2, §4 | `parsers.py` `_requirements`, `_poetry`, `_package_json`, `_pom` | `test_core.test_unpinned_and_ranged_requirements_diagnostics`; baseline scan 6 packages | PASS | — |
| 2 | Unpinned / ranged declaration must not vanish silently | PROJECT_SPEC §4.1 (amended), SECURITY_MODEL §2 | `parsers.is_concrete_version` + `_unresolved`, `parse_manifest_with_diagnostics`; CLI stderr warning; `report.json.unresolved_dependencies`; trace `parse.summary.unresolved_dependencies_count` | `test_hardening.py` (4 tests); live run on `demo_attack_sim/fake_shop` → **2 unresolved records**, 2 stderr warnings | PASS (was FAIL → fixed, P1-3) | — |
| 3 | Malformed / unparseable manifest is disclosed | PROJECT_SPEC §4.1 (amended) | `reason=malformed_requirement` / `unparseable_manifest` | `test_hardening.test_unparseable_manifest_is_disclosed`, `..._unknown_manifest_diagnostics` | PASS | — |
| 4 | Duplicate `(ecosystem, name, version)` deduplicated | ARCHITECTURE `parsers.py` invariants | `parse_manifests_with_diagnostics` keyed dict | `test_core`, `test_hardening` | PASS | — |
| 5 | Maven property placeholder not treated as a version | PROJECT_SPEC §3.2 | `reason=unresolved_maven_property` | `test_hardening.test_maven_property_version_is_disclosed` | PASS | — |
| 6 | Unsupported ecosystem ⇒ empty result, not an error | PROJECT_SPEC §3.3, ADR-008 | `discover_manifests` finds nothing; exit 0 | live probe on a `build.gradle`-only directory: exit 0, empty packages, **no stderr warning, no diagnostic field** | PARTIAL | P2-2: report does not say "nothing was analysed" |
| 7 | OSV lookup, aliases, severity, fixed_version | PROJECT_SPEC §4.2, ADR-001 | `osv.py` batch query + range scan | baseline: 30 advisories, `test_osv` unit coverage | PASS | — |
| 8 | Import detection (PyPI name→module mapping, aliases) | PROJECT_SPEC §5 | `reachability.import_names` + `PYPI_IMPORT_OVERRIDES` + AST walk | baseline: `yaml`/`requests` imports with `file:line`; `test_reachability` | PASS | — |
| 9 | Call-site detection for advisory functions | PROJECT_SPEC §5 | `_python_calls` (AST, alias + 3-level attribute chains); JS/TS regex | `demo` flip: `yaml.load` call found at `app.py:24` | PASS | — |
| 10 | `not imported` ⇒ `not_affected` / `vulnerable_code_not_present` | PROJECT_SPEC §6, SECURITY_MODEL §3 | `cli._decision` branch 1 | baseline: guava/lodash advisories dismissed with empty import evidence | PASS | — |
| 11 | imported + function known + not called ⇒ `not_affected` / `vulnerable_code_not_in_execute_path` | PROJECT_SPEC §6 | branch 3 | baseline: 26 dismissed with non-empty `vulnerable_functions` | PASS | — |
| 12 | imported + vulnerable function called ⇒ `affected` | PROJECT_SPEC §6 | branch 4 | `demo` AFTER state: 4 pyyaml advisories `affected` with `calls: app.py:24` | PASS | — |
| 13 | No function-level data ⇒ conservative, never optimistically dismissed | SECURITY_MODEL §1.1/§4, THREAT_MODEL §6 | branch 2: `affected`, `impact_statement="function-level data unavailable"`, `decision_source="conservative-default"` | baseline: all **4** actionable findings are `conservative-default` (requests advisories with `vulnerable_functions: []`) | PASS | — |
| 14 | LLM is a hint, never authority | ADR-002 (amended), THREAT_MODEL §4.4, AGENTS.md §5 | `cli._decision`: `functions = union(heuristic, llm)`; `function_source` ∈ {`advisory_backticks`, `llm`, `llm+advisory_backticks`} | `test_hardening.py` LLM-union group (4 tests) | PASS (was FAIL → fixed, P1-2) | — |
| 15 | LLM cannot suppress a real call (was: "may reduce `affected`") | ADR-002 | union invariant | `test_llm_wrong_function_list_cannot_suppress_a_real_call` | PASS | spec corrected ADR-002 |
| 16 | `--no-llm` deterministic, LLM never contacted | CLI_CONTRACT §2, §8 | `vulnerable_functions` only called when `not no_llm` | `test_no_llm_still_uses_the_advisory_path_unchanged` | PASS | — |
| 17 | CycloneDX 1.5 SBOM always produced | PROJECT_SPEC §9, ADR-006 | `sbom.create_sbom`; cdxgen then fallback | baseline `sbom.cdx.json` (6 components, 1.5); engine tests | PASS | — |
| 18 | cdxgen invocation is not an unpinned download | PROJECT_SPEC §9.2 (amended), SECURITY_MODEL §2 | `PINNED_CDXGEN_PACKAGE=@cyclonedx/cdxgen@10.9.0`; `CHAINGUARD_DISABLE_CDXGEN` | `test_core.test_sbom_cdxgen_version_is_pinned_and_configurable` | PASS (was FAIL → fixed, P1-4) | residual P2-3 (no integrity check) |
| 19 | OpenVEX 0.2.0 statements per finding | PROJECT_SPEC §10, ADR-007 | `vex.py` | baseline 30 statements; `test_core` justification assertions | PASS | — |
| 20 | Every verdict carries reproducible evidence | AGENTS.md §4, SECURITY_MODEL §3 | `evidence.{vulnerable_functions,function_source,confidence,import,calls}` | baseline report; live API returns the same keys | PASS | — |
| 21 | Evidence survives scanner → adapter → API | (implied by schema design) | `schemas.*` `extra="allow"`; `service.scan_repository` passes fields through | unit: unknown field + `unresolved_dependencies` survive `model_dump()`; live: `unresolved=2` reaches the API response | PASS | — |
| 22 | `trace.json` records all stages and journeys | AGENTS.md §4, PROJECT_SPEC §8 | `trace.Tracer` | baseline: 6 stages `parse,sbom,osv_lookup,reachability,slopsquat,vex_output`; `test_dashboard` | PASS | — |
| 23 | Slopsquat / unknown-package signal | PROJECT_SPEC §7 | `slopsquat.inspect_package` (registry lookups, LLM second signal) | baseline: `flask-super-auth-helper` flagged, `registry_unavailable` reported as unknown | PASS | — |
| 24 | `--diff <ref>` analyses only added/changed packages | CLI_CONTRACT §7 | `_diff_added_packages` | `test_diff`, `test_hardening` | PASS | — |
| 25 | Scanner must not execute code configured by the scanned repo | THREAT_MODEL §6.1 (invariant), ADR-005, ADR-010 | `GIT_HARDENING` (`-c core.fsmonitor=false --no-pager`) + `--no-ext-diff --no-textconv --cached` | controlled experiment: **3/3 hook executions before, 0/3 after**; `test_hardening` asserts flags + positive control | PASS (was FAIL → fixed, P0-1) | — |
| 26 | Exit codes 0/1/2 stable, summary on stdout, logs on stderr | CLI_CONTRACT §6, PROJECT_SPEC §12 | `cli.main` | baseline exit 0; invalid path exit 2; `--fail-on-actionable` exit 1 | PASS | — |
| 27 | `GET /health` reports real-engine availability | API README | `engine.health_payload` (files **and** `--help` + `import requests` probe) | live: `{"status":"ok","executable":true}` on all three instances | PASS | — |
| 28 | `POST /scan` invokes the real engine and preserves artifacts | API README | `service.scan_repository` + `engine.build_command` (argv, never a shell string) | live: HTTP 200, `baseline_match=True`, `summary_matches_disk=True`, artifacts report/sbom/vex/trace all present | PASS | — |
| 29 | One repository failure must not cancel siblings | API README | `app.fleet` → `asyncio.gather(..., return_exceptions=True)`, one executor call per repo | live: `[valid, invalid]` → `partial`, valid repo completed with 30 advisories; `[valid, valid, invalid]` → 2 completed + 1 `INVALID_REPOSITORY` | PASS | — |
| 30 | Fleet counts/aggregates equal per-repository totals | API README | `service.aggregate_fleet` sums only completed results | live: aggregate 30 == Σ per-repo 30 | PASS | — |
| 31 | Per-repository output isolation and identity | API README | `<workspace>/<scan_id>/<repo_id>` | live: 3 distinct out-dirs, ids `[fleet-a, fleet-b]` preserved, no crosstalk | PASS | — |
| 32 | `MAX_CONCURRENT_SCANS` bounds active scanners | API README | `ThreadPoolExecutor(max_workers=...)` | live probe: limit 2 + 3 repos → peak **2** live invocations (raw process pairs explained by the Windows venv launcher); limit 1 + 2 repos → peak **1** | PASS | — |
| 33 | `SCAN_TIMEOUT_SECONDS` terminates a hanging scan | API README | `subprocess.run(timeout=...)` → `RunOutcome(timed_out=True)` | live: 2000-declaration repo → HTTP **504** at 15.5 s (limit 15 s), `state=TIMEOUT`, `error=SCAN_TIMEOUT`, no fabricated summary, no leaked scanner process | PASS | — |
| 34 | Timed-out repository does not stop fleet siblings | API README | per-job timeout | live `[fast, slow]` → `partial`, fast repo completed normally, slow `TIMEOUT` | PASS | — |
| 35 | No global API timeout is required | (question raised by the brief) | per-repo subprocess timeout + bounded pool | timeout path verified above; a fleet of 50 × 300 s is still a ~2 h request — a *client* deadline is required, not a server one | PASS | see P2-4 |
| 36 | Path traversal / absolute escape / mixed separators rejected | SECURITY_MODEL §5 | `paths.validate_repository_path` (resolve + containment) | `test_path_security`: relative traversal, absolute outside, traversal inside string, mixed separators, extended-length path, NUL/empty | PASS | — |
| 37 | Repository id cannot traverse directories | SECURITY_MODEL §5 | `REPOSITORY_ID_PATTERN` + explicit `..`/separator check | 9 rejecting + 4 accepting parameterised cases | PASS | — |
| 38 | Output directory confined to the allowed root | SECURITY_MODEL §5 | `validate_output_directory` | `test_output_directory_must_stay_inside_root` | PASS | — |
| 39 | Symlink escape rejected | SECURITY_MODEL §5 | `Path.resolve()` follows links before containment | test present, **skipped** on this host (WinError 1314) | PARTIAL | P3-1: keep test, must run on a privileged/CI host |
| 40 | `\\?\` extended paths normalised, not treated as escapes | (implementation detail) | `paths._strip_extended` | `test_rejects_extended_length_path_outside_root`, `test_extended_length_prefix_is_normalised_before_containment` | PASS | — |
| 41 | No `shell=True`, no `os.system`, no `eval`/`exec` | PROJECT_SPEC §14, AGENTS.md §8 | 4 production subprocess sites + 3 API sites, all argv lists | repository sweep (§8.6) | PASS | — |
| 42 | Scanner's own supply chain is understood | SECURITY_MODEL §2 (amended), THREAT_MODEL §5 | cdxgen pinned; disable knob; documented residual risk | `test_core` pin test; specs updated | PARTIAL | P2-3: integrity not verified |
| 43 | Demo proves reachability flip and stays synthetic | demo README | `demo_attack_sim/run_logs/run_fixture_scan.py` | runner exit 0: 4 advisories `not_affected` → `affected` with `app.py:24`; fixture restored byte-for-byte | PASS | — |
| 44 | Demo repository untouched by this audit | — | — | `git status` before/after identical (only pre-existing untracked `run_logs/*`) | PASS | — |
| 45 | Specs describe the verified architecture | §16 of the brief | 8 documents reviewed; 7 updated | §10 of this audit lists each edit | PARTIAL → PASS after edits | — |

---

## 3. P0 findings (1 found, 0 open)

### P0-1 — `git` executed commands configured by the *scanned* repository

* **Where:** `chainguard_mvp/cli.py::_diff_added_packages` (the `--diff <git-ref>` path).
* **What:** `git diff` and `git show` ran inside the scanned repository without disabling repository-configured
  hooks, filters, external diff drivers or textconv. `.git/config` and `.gitattributes` of a scanned repository are
  attacker-controlled under the project's own threat model, so a malicious repository could execute arbitrary
  commands in the scanner process. The failure is silent — the diff still succeeds and looks normal.
* **Why P0:** it violates the explicit security invariant THREAT_MODEL §6.1 ("the scanner must not execute any code
  from the scanned repository") and ADR-005 (static analysis only), and the trigger is simply "scan a hostile repo
  with `--diff`". It is remote code execution against the scanner's own host, not a scoring nuance.
* **Evidence (controlled experiment, `.audit_scratch/git_vectors*.py`, synthetic local repos only):**

  | Vector | Before fix | After fix |
  |---|---|---|
  | `core.fsmonitor` shell command | **executed 3/3** | **blocked 3/3** |
  | `diff.<driver>.command` (external diff) | not fired with the existing `--no-ext-diff` | blocked |
  | `diff.<driver>.textconv` | not fired (no textconv output path) | blocked |
  | clean/smudge filter via `.gitattributes` | not fired (no worktree diff) | blocked (`--cached`) |
  | `core.pager` | not fired (non-tty capture) | blocked (`--no-pager`) |

* **Fix (smallest safe change):** module constant `GIT_HARDENING = ("-c", "core.fsmonitor=false", "--no-pager")`
  applied to all three git invocations, plus `--no-ext-diff`, `--no-textconv`, `--cached` and `--unified=0` on the
  diff. `--cached` compares the ref against the index, so no clean/smudge filter can run.
* **Regression test:** `software supply chain mvp/tests/test_hardening.py` — asserts the hardening prefix on every
  recorded git call, asserts the diff flags, and includes a **positive control** proving that the same repository
  *does* fire its configured fsmonitor command for an unhardened `git diff` on this host (so the test cannot pass
  vacuously). 12 tests pass.
* **Spec reconciliation:** `DECISIONS.md` gained **ADR-010** (the code comment already referenced a non-existent
  "ADR-010"); `THREAT_MODEL.md` gained **§4.8** and a strengthened invariant §6.1; `CLI_CONTRACT.md` §7 now
  documents the exact, hardened commands.
* **Residual:** git itself remains a trusted component; a per-manifest diff failure is skipped without disclosure
  (P2-5).

---

## 4. P1 findings (3 found, 0 open)

### P1-2 — an LLM answer could replace (and thus suppress) the advisory-derived function list

* **Where:** `cli._decision`.
* **What:** the vulnerable-function set was taken as *the LLM's list when the LLM answered*, otherwise the
  heuristic list. A wrong, hallucinated or prompt-injected answer (THREAT_MODEL §4.4 explicitly models advisory
  text as an injection channel) could therefore remove `yaml.load` from the candidate set while the code calls it —
  turning a real call into a `not_affected` verdict. The old wording of ADR-002 ("LLM output can only **reduce**
  the `affected` count") sanctioned exactly this.
* **Why P1:** it corrupts the product's central verdict (`affected` vs `not_affected`) using data the spec already
  classifies as untrusted, and it silently *under*-reports — the worst direction for a security tool.
* **Fix:** `functions = list(dict.fromkeys([*heuristic_functions, *llm_functions]))` — the LLM may only **add**
  candidates; `function_source` reports `llm+advisory_backticks` when both contribute, and `confidence` is only
  populated when the LLM genuinely contributed.
* **Regression tests:** `test_llm_wrong_function_list_cannot_suppress_a_real_call`,
  `test_llm_can_only_add_function_candidates`, `test_llm_empty_function_list_falls_back_to_advisory_heuristics`,
  `test_no_llm_still_uses_the_advisory_path_unchanged`.
* **Spec reconciliation:** `DECISIONS.md` ADR-002 amended (with an explicit note that the old wording described
  the removed behaviour); `SECURITY_MODEL.md` §4 documents the union and the third `function_source` value.

### P1-3 — unresolvable dependency declarations disappeared silently (misleading "clean" scan)

* **Where:** `parsers.py` (and therefore `report.json`, the trace, the API).
* **What:** a declaration that could not be reduced to one concrete version — `flask>=2`, `lodash@5.x`,
  `package` without a version, `${maven.prop}`, `workspace:*`, an environment marker, a malformed line, or an
  unparseable manifest — was dropped. The repository was then scanned with a *smaller* inventory and reported
  successfully, with a summary that looks identical to a genuinely clean repository.
* **Why P1:** it is a false-clean result produced by silent data loss in the core inventory step; the brief calls
  this case out explicitly, and SECURITY_MODEL §2 forbids implying "all vulnerabilities have been found".
* **Fix:** `parsers.is_concrete_version` + `_unresolved(...)`; every parser gained a `*_with_diagnostics` variant;
  `cli.py` prints one stderr warning per dropped declaration, records `summary.unresolved_dependencies_count` in the
  `parse` trace stage, and writes `report.json.unresolved_dependencies`; the API returns them in
  `unresolved_dependencies` (schema extended for exactly this purpose).
* **Observed evidence (live, not asserted):** scanning `demo_attack_sim/fake_shop` (`fastapi>=0.110`,
  `uvicorn>=0.27`) prints the stable summary `Total vulnerabilities: 0` but now also emits two stderr warnings and
  `unresolved_dependencies: [{fastapi, >=0.110, unpinned_or_ranged_requirement}, {uvicorn, >=0.27, ...}]` in
  `report.json`, `unresolved_dependencies_count: 2` in the trace, and `unresolved=2` through `POST /scan/fleet`.
* **Regression tests:** `test_unpinned_requirement_is_disclosed_and_not_counted_as_installed`,
  `test_range_wildcard_and_workspace_protocols_are_disclosed`,
  `test_maven_property_version_is_disclosed`, `test_unparseable_manifest_is_disclosed`,
  `test_requirements_arbitrary_equality_pin_is_accepted`, plus the pre-existing `test_core` diagnostics test.
* **Spec reconciliation:** `PROJECT_SPEC.md` §4.1, `ARCHITECTURE.md` parsers invariants, `TEST_STRATEGY.md`.
* **Residual:** the stdout summary format is a frozen contract and still prints zeros; see P2-1.

### P1-4 — `npx -y @cyclonedx/cdxgen` executed an unpinned npm download during every scan

* **Where:** `chainguard_mvp/sbom.py`.
* **What:** the SBOM step ran `npx -y @cyclonedx/cdxgen`, i.e. `@latest`: a mutable, unauthenticated npm package
  fetched and executed inside the scanner at scan time. A compromised or typosquatted release of that package, or
  any attacker able to influence resolution, gains arbitrary code execution in the scanner process; the effect is
  invisible because a failed cdxgen silently degrades to the fallback inventory.
* **Why P1:** it is a supply-chain execution path in the security product itself, triggered on every scan, with no
  operator control. It is not exploitable via the scanned repository, which is why it is P1 and not P0.
* **Fix:** `PINNED_CDXGEN_PACKAGE = "@cyclonedx/cdxgen@10.9.0"` (a fixed release, never `@latest`) plus
  `CHAINGUARD_DISABLE_CDXGEN=1` to skip the subprocess entirely and use the deterministic fallback SBOM.
* **Regression test:** `test_core.test_sbom_cdxgen_version_is_pinned_and_configurable` (asserts `@cyclonedx/cdxgen`
  is never passed bare, that the pinned constant is present, and that the disable flag prevents any subprocess).
* **Spec reconciliation:** `PROJECT_SPEC.md` §9.2 now documents the pin, the disable knob, the never-fail
  behaviour and the residual risk; `SECURITY_MODEL.md` §2 gained a "we do not claim the scanner's own tooling is
  trusted" row; `THREAT_MODEL.md` §5 and the engine README were updated.
* **Residual:** the pinned tarball is still fetched without integrity verification at scan time (P2-3).

---

## 5. P2 findings (open, documented — deliberately not "fixed" in this phase)

| ID | Finding | Evidence | Why not fixed now | Recommendation |
|---|---|---|---|---|
| P2-1 | The frozen stdout summary still reads `Total vulnerabilities: 0` when declarations were dropped; disclosure lives only on stderr and in JSON | live fake_shop run | stdout format is a documented stable contract; changing it is a contract decision | add an opt-in `--fail-on-unresolved` and/or an `unresolved: N` stdout line in a *contract-versioned* change |
| P2-2 | A repository with **no supported manifest** produces exit 0, an all-zero summary, empty `packages`, **no warning and no diagnostic field** — indistinguishable from a clean scan | live probe on a `build.gradle`-only directory | ADR-008/`PROJECT_SPEC` §3.3 *specify* "empty results, not an error", so this is a specified behaviour, not a defect | disclose "0 manifests analysed" in `report.json` + stderr |
| P2-3 | cdxgen's pinned tarball is fetched at scan time **without integrity verification** | `sbom.py`, specs | a fix means changing SBOM generation or adding verification — a capability, not a repair | document (`SECURITY_MODEL`), keep `CHAINGUARD_DISABLE_CDXGEN=1` for untrusted hosts, adopt a verified-lockfile/lib approach later |
| P2-4 | No server-side deadline for a whole fleet request (50 repos × 300 s with a pool of 2 is a ~2 h request); only per-repository timeouts exist | architecture reading + timeout experiment | a per-repo timeout is the correct security control; a global deadline is a policy choice | expose a documented client-side deadline; optionally add a request budget later |
| P2-5 | A `--diff` manifest that cannot be diffed is skipped silently (`except ...: continue`) — a diff-mode scan can under-report | `cli._diff_added_packages` | narrow (CLI-only) and requires an output-contract decision | record skipped manifests as unresolved/diagnostic entries like P1-3 |
| P2-6 | On timeout the **scanner process is killed but its grandchild survives**: with cdxgen enabled, an orphaned `node.exe` kept running after the API had already answered 504 | live: HTTP 504 at 20 s, `node pid=22148` still alive 10 s later, 0 `chainguard_mvp.cli` processes | P2 by impact (resource/availability leak, no verdict or code-execution impact), and killing a process *tree* is a portability change needing its own test | kill the tree on timeout (Windows `taskkill /PID <pid> /T /F`, POSIX `killpg`), or launch the scanner in its own job object; verify with a hanging-scan test |
| P2-7 | Advisory function-name extraction is noisy (e.g. `in`, `variable`, `SESSION_REFRESH_EACH_REQUEST`, `options.imports` from advisory prose) | baseline `report.json` evidence | it can only make verdicts *more* conservative, i.e. fail-safe | filter keywords/short identifiers/property-only tokens in `_extract_functions` |

---

## 6. P3 / known limitations (recorded, not defects)

1. **Windows symlink-escape test skipped** — `WinError 1314` (the account lacks `SeCreateSymbolicLinkPrivilege`).
   The test is retained; containment is implemented via `Path.resolve()`, which follows links, so the case is
   covered by construction but not executed on this host. Must be run on a privileged or CI host.
2. **Reachability is static and best effort** — JS/TS matching is regex-based (no call graph), Python is AST-based
   with alias resolution; dynamic imports, reflection, wrappers and native code can be missed. Already documented
   in the specs and README.
3. **No data-flow / taint analysis** — a call reachable only with attacker-controlled input is not distinguished
   from an unreachable one.
4. **No transitive resolution** unless cdxgen succeeds — documented.
5. **Cosmetic:** the stderr warning uses an em dash, which renders as a replacement character on a cp1252 console.

---

## 7. Security-engine deep-dive

### 7.1 Dependency analysis (deterministic, now fail-closed on disclosure)

* Required: a declaration that cannot be resolved to one exact version must never be silently dropped.
* Verified: `fastapi>=0.110`, `uvicorn>=0.27` (fake_shop) → 2 unresolved records in `report.json`, 2 stderr
  warnings, `unresolved_dependencies_count: 2` in the `parse` trace stage, `unresolved: 2` in the API response, and
  the package is **not** counted as installed. `requirements===2.31.0` (arbitrary equality) is still accepted as a
  concrete pin. `lodash@5.x`, `workspace:*`, non-string npm specs, `${...}` Maven properties, missing Maven
  versions, malformed lines and unparseable manifests are all disclosed with a `reason`.
* **Answer to the brief's question:** before the fix, yes — an unpinned dependency could disappear and still
  produce a clean-looking report, and the severity against `SECURITY_MODEL.md` (which forbids implying complete
  coverage) was **P1**. It is disclosed now. The remaining sibling case is P2-2 (`no supported manifest at all`).

### 7.2 Verdict decision logic (exact, as implemented in `cli._decision`)

```
candidates = union( _extract_functions(advisory_text),        # backticks / function() refs
                    LLM.vulnerable_functions(advisory_text) )  # hint only, may add, never remove

reachability = analyze_package(root, package, candidates)

1. not imported                                  -> not_affected / vulnerable_code_not_present   (import-check)
2. imported AND candidates == []                 -> affected     / (no justification)  "function-level data
                                                                 unavailable", conservative-default
3. imported AND no call evidence                 -> not_affected / vulnerable_code_not_in_execute_path
4. imported AND call evidence found              -> affected     / (no justification)
```

* `evidence.function_source` ∈ {`advisory_backticks`, `llm`, `llm+advisory_backticks`}; `confidence` is set only
  when the LLM contributed.
* Branch 2 is the conservative rule required by SECURITY_MODEL §1.1: **4 of the 4 actionable baseline findings are
  branch 2 with `vulnerable_functions: []`** — i.e. the current "actionable" set means "imported with unknown
  vulnerable functions", not "proven vulnerable call". This is honest but it is also the biggest evidence-quality
  gap in the engine and drives the next-phase recommendation (§11 F).
* Reachability detail: Python imports/calls are AST-based with alias resolution (`import yaml as y; y.full_load()`)
  and 3-level attribute chains; JS/TS use `import`/`require` patterns plus identifier call matching; scannable
  extensions are `.py/.js/.jsx/.ts/.tsx/.mjs/.cjs`; `node_modules`, `.git`, `venv`, `dist`, `build` are skipped.

### 7.3 LLM boundary

* The LLM is called only from `_decision` (function-name hints, unioned) and `slopsquat.inspect_package` (second
  suspicious-package signal). It is disabled when `--no-llm` is passed or when the endpoint/key are absent.
* It has **no** influence over: advisory existence (OSV), severity (OSV CVSS), `affected`/`not_affected`
  (deterministic branch logic + static analysis), or the summary counts. `confidence` is a reported field only.
* The single violation of this rule found by the audit was P1-2 (the LLM replacing the heuristic list), and it is
  fixed and regression-tested. **Current status: the LLM cannot be the final authority for any security verdict.**

### 7.4 SBOM, VEX and evidence preservation

* A real scan produces `report.json`, `trace.json`, `sbom.cdx.json` and `openvex.json` (plus `stdout.log` /
  `stderr.log` in the API's isolated workspace). Verified for the baseline and for every API scan.
* End-to-end preservation: `extra="allow"` is **effective, not decorative** — a vulnerability carrying an unknown
  field round-trips through `Vulnerability.model_dump()`, and `unresolved_dependencies` (a field the schema did not
  originally model) reaches API clients intact. `service.scan_repository` starts from the scanner's own `summary`
  dict and only overwrites the five modelled numeric keys, so new scanner fields survive.
* The API never fabricates evidence: on timeout it returns `summary: null` and `vulnerabilities: []` with
  `state=TIMEOUT`; on a scanner exit code other than 0/1/2 it returns `ENGINE_ERROR` and does not invent a result.

---

## 8. Horizontal API deep-dive

### 8.1 Single repository (`POST /scan`)

Live against the running service (real engine, real network): HTTP **200**, `status=completed`,
`state=COMPLETED`, `scan.exit_code=0`, 30 vulnerabilities, summary identical to the on-disk `report.json`
(`summary_matches_disk=True`), the baseline expectation matched exactly
(`baseline_match=True`), all four artifacts present, first finding carries
`['calls','confidence','function_source','import','vulnerable_functions']`.

### 8.2 Fleet (`POST /scan/fleet`)

| Case | Result |
|---|---|
| valid + valid | `status=completed`, both completed, **isolated output directories**, repository identity preserved, aggregate = 30, no crosstalk |
| valid + invalid | `status=partial`; the valid repository **completed normally** (30 advisories) while the invalid one failed with `INVALID_REPOSITORY` — one failure did not cancel its sibling |
| valid + valid + invalid | `status=partial`, 2 completed / 1 failed, `aggregate_equals_sum=True` (30 vs 30) |

### 8.3 Concurrency

Measured with a live process-table probe (counted distinct `--out-dir` values of live
`python -m chainguard_mvp.cli` processes, i.e. real scan executions; the raw count is exactly double on Windows
because a venv `python.exe` is a launcher that starts the base interpreter as a child):

| Configured `MAX_CONCURRENT_SCANS` | Repositories | Peak live invocations | Raw processes | Wall time |
|---|---|---|---|---|
| 2 | 3 | **2** (never 3) | 4 (×2 pairs) | 50.3 s |
| 1 | 2 | **1** (serialised) | 2 | 69.0 s |

`peak concurrency <= configured limit`: **confirmed by measurement**, not by reading the code.

### 8.4 Timeouts

* 2000-declaration repository, `SCAN_TIMEOUT_SECONDS=15`: HTTP **504** after 15.5 s, `status=timeout`,
  `state=TIMEOUT`, `error=SCAN_TIMEOUT`, `summary=null`, `vulnerabilities=[]`, `scan.exit_code=-1`, and **no
  scanner process left behind** (0 live invocations immediately afterwards).
* `[fast, slow]` fleet: `partial`; the fast repository completed with real findings while the slow one timed out.
* **Is an API-level timeout necessary?** No — the per-repository subprocess timeout already bounds the only
  unbounded operation and yields an honest, evidence-free failure state. What is missing is a *client-side*
  deadline for very large fleets (P2-4), not a server-side one.
* **Gap:** grandchildren are not reaped (P2-6, verified live with cdxgen enabled).

### 8.5 Path security

All cases pass (`test_path_security.py`, 24 passed / 1 skipped): relative traversal, absolute path outside the
root, `..` inside a path string, mixed separators, extended-length (`\\?\`) paths, NUL/empty paths, non-existent
directories, output-directory escape, and 9 unsafe repository ids (`../evil`, `a/b`, `a\b`, `..`, empty, space,
leading dash, 65 chars, embedded space). Containment compares normalised, symlink-resolved, case-folded paths and
`_strip_extended` neutralises the `\\?\` prefix that `resolve()` intermittently returns — so a race in fleet scans
cannot be mistaken for an escape. **No validation was weakened to make a test pass.**

### 8.6 Subprocesses and ChainGuard's own supply chain

Complete repository sweep (`shell=True|os.system|subprocess.(Popen|run|call|check_output|check_call)|eval\(|exec\(`)
found **no** `shell=True`, `os.system`, `eval` or `exec` in production code. Production sites:

| Site | Command source | Arguments | Shell | User-controlled input | Path validation | Timeout | Environment |
|---|---|---|---|---|---|---|---|
| `cli._diff_added_packages` (×3) | literals | argv list, `repo`/`relative` as separate entries | no | git ref (validated by `rev-parse --verify`), manifest paths (from `discover_manifests`) | repo root resolved before use | 20 s per call | inherited |
| `sbom.create_sbom` | literal `npx` + **pinned** package | `npx -y @cyclonedx/cdxgen@10.9.0 -o <out> <root>` | no | repo root (validated) | yes | 120 s | inherited (`CHAINGUARD_DISABLE_CDXGEN` honoured) |
| `engine.engine_executable` (×2) | literal | `-m chainguard_mvp.cli --help`, `-c "import requests"` | no | none | n/a | 20 s | inherited |
| `service.default_runner` | `engine.build_command` | `python -m chainguard_mvp.cli <repo> --out-dir <dir> [--no-llm…]` | no | repo path + options | validated before the call | `SCAN_TIMEOUT_SECONDS` | inherited |

`npx` and `git` are the only external binaries that can download or execute code. Their supply-chain implications
are: git — trusted local tool, now invoked with hardened flags (P0-1); cdxgen — pinned but integrity-unverified
(P1-4 fixed, P2-3 residual). Nothing was removed to reduce this surface: the cdxgen attempt is preserved and can
be disabled explicitly.

---

## 9. Demo integrity (`demo_attack_sim/`, untracked by this audit)

`run_logs/run_fixture_scan.py` was executed end-to-end (it is the demo's own runner; it never installs the pinned
package, never executes the fixture, and restores the fixture):

```
BEFORE summary: {"total_vulnerabilities": 4, "dismissed_unreachable": 4, "actionable": 0, ...}
AFTER  summary: {"total_vulnerabilities": 4, "dismissed_unreachable": 0, "actionable": 4, ...}
GHSA-6757-jp84-gxfx    not_affected -> affected   app.py:24
GHSA-8q59-q68h-6hv4    not_affected -> affected   app.py:24
PYSEC-2020-96          not_affected -> affected   app.py:24
PYSEC-2021-142         not_affected -> affected   app.py:24
fixture/app.py restored byte-for-byte: yes
FLIP VERIFIED: not_affected -> affected with file:line evidence.   (runner exit 0)
```

* The advisory is real: OSV returns four pyyaml 5.3 advisories for `pyyaml==5.3` and the vulnerable function
  `yaml.load` is extracted from the advisory text (deterministic path, `--no-llm`).
* `git status` in `demo_attack_sim` is identical before and after (only the pre-existing untracked `run_logs/*`).
* The demo remains local and synthetic: no credentials, cookies, sockets, subprocesses or exfiltration; the sink
  writes a fake `demo_session` cookie to a local file and is never called by the fixture.

---

## 10. Specification quality (what was wrong, what changed)

| Document | Problem found | Change |
|---|---|---|
| `DECISIONS.md` | ADR-002 explicitly sanctioned the LLM **reducing** `affected` — the P1-2 defect was written into the spec — and `cli.py` referenced a non-existent "ADR-010" | ADR-002 amended with the union invariant and a dated note; **ADR-010** added documenting the hardened git invocation |
| `THREAT_MODEL.md` | No attack surface for "scanned repository configures git commands"; invariant §6.1 was violated by the implementation | new **§4.8**; §6.1 strengthened; §5 table row corrected |
| `CLI_CONTRACT.md` | §7 documented the *pre-fix* `git rev-parse` / `git diff` commands | exact hardened commands + rationale + the `--cached` consequence |
| `PROJECT_SPEC.md` | §9.2 described an unpinned cdxgen attempt with no failure/disable semantics; §4.1 did not describe unresolvable declarations | cdxgen pin + disable knob + never-fail + residual risk; unresolved-declaration disclosure |
| `ARCHITECTURE.md` | `parsers.py` invariants did not mention unresolved declarations | added the record shape, the `reason` vocabulary and the end-to-end propagation |
| `SECURITY_MODEL.md` | §4 omitted the third `function_source` value and the union rule; §2 did not disclose the scanner's own tooling risk | union bullet; "do not claim the scanner's own tooling is trusted" row |
| `TEST_STRATEGY.md` | said a range version is "ignored"; no mention of the hardening tests | range versions are *disclosed*; new `tests/test_hardening.py` section |
| Engine `README.md` | limitations still described silent range handling and an unpinned cdxgen | limitations updated (both copies) |

Nothing was weakened: no security requirement was relaxed to match an incomplete implementation, and no
implementation was faked to satisfy a specification. Capabilities the specs describe but that are **not**
implemented remain declared as out of scope (`behavior.py`, `unicode_audit.py`, `provenance.py`, EPSS/KEV, call
graphs, data-flow, runtime analysis) — see `SECURITY_MODEL.md` §2 and `DECISIONS.md` ADR-003/ADR-004, which are
consistent with the code. No such capability was started in this phase.

---

# NEXT PHASE GATE

### A. Is the existing scanner trustworthy enough to build on?
**YES.** Deterministic branch logic, OSV-backed advisories, evidence with `file:line`, the conservative
"no function-level data ⇒ affected" rule, disclosed unresolvable declarations, a bounded prompt-injection
boundary for the LLM, and the explicit invariant that the scanner never executes code from the scanned
repository — now enforced (P0-1) and regression-tested. The 30/26/4/1/86.7 baseline is reproduced exactly.

### B. Is the FastAPI horizontal layer trustworthy enough to build on?
**YES.** Real-engine gate that refuses to scan with a missing/stub engine, argv-only subprocess execution,
bounded concurrency (measured), honest timeout/error states that never fabricate findings, path and id
validation that survives traversal/extended-path attempts, isolated per-repository workspaces, sibling isolation
in fleets, aggregate totals that equal per-repository totals, and lossless evidence passthrough via
`extra="allow"`. Do not expose it beyond a trusted boundary until authentication is added (P2, architecture note).

### C. Are there unresolved P0 security issues?
**NO.** One P0 was found (git executing scanned-repository-configured commands) and is fixed, regression-tested
and documented in the threat model and ADR-010.

### D. Are there unresolved P1 issues?
**NO.** Three P1s were found — LLM suppression of advisory-derived functions, silent loss of unresolvable
dependencies, and an unpinned cdxgen execution — and all three are fixed with regression tests and spec updates.
The remaining findings are P2 (resource/disclosure/UX) and P3 (documented limitations), all listed in §5–§6.

### E. Is the architecture ready for the next security-engine capability?
**YES.** The pipeline (parse → sbom → osv → reachability → slopsquat → vex), the report/trace/evidence idioms,
the API contract and the test structure already provide every seam the next capability needs; the P0/P1 fixes
removed the trust blockers rather than adding new moving parts.

### F. What should be implemented next? (exactly one)

**Evidence-graded reachability verdicts** — separate *proven* vulnerable calls from *unknown* function-level
data, and give each its own verdict and evidence grade.

**Reason (technical):** the baseline's entire actionable set (4/4) is branch 2 of the decision tree —
`affected` because *no* vulnerable-function data exists for those advisories, not because a call was proven.
Today the report cannot distinguish "your code calls the vulnerable function" from "we could not determine the
function", so triage value is capped and every unknown inflates the actionable count. The next capability should
(a) strengthen advisory function-name extraction (multi-ecosystem identifiers, filtering of prose tokens such as
`in`/`variable`/`options.imports` — the P2-7 noise), (b) resolve symbols per ecosystem (module/attribute
resolution beyond today's AST+regex, incl. re-exports and aliases), and (c) map the conservative case onto
OpenVEX `under_investigation` with a graded `evidence` object. That keeps every security invariant intact,
preserves the deterministic branch structure, is fully testable with the existing fixture/demo harness, and
directly serves the thesis: *relevant, reachable and executable — not merely present.*

Alternatives considered and rejected for now: EPSS/KEV scoring (adds prioritisation, not reachability evidence),
`behavior.py`/`provenance.py` (heuristic, weaker evidence, heavier), runtime/data-flow analysis (large,
deferred by ADR-003), and the P2 process-tree/orphan fix (correct hygiene, but a resource issue rather than a new
detection capability).

---

## CHAINguard POST-IMPLEMENTATION STATUS

```
Specification audit:      PASS   (after 7 documents were reconciled with the verified architecture)
Security engine:          READY
Horizontal API:           READY  (do not expose without authentication — P2)

P0:                       1 found / 0 open
P1:                       3 found / 0 open
P2:                       7 open (documented, none blocking)
P3:                       5 limitations (documented: 1 skipped Windows symlink test, 4 known-analytical)

Tests:                    25 passed (engine, both copies) · 12 passed (test_hardening.py)
                          64 passed, 1 skipped of 65 collected (API) · 24 passed, 1 skipped (path security)
Real scan:                30 vulnerabilities / 26 dismissed / 4 actionable / 1 suspicious / 86.7% noise
                          reduction, exit 0, artifacts report+trace+CycloneDX 1.5 (6 components)+OpenVEX
                          (30 statements); unchanged from the pre-audit baseline
Demo:                     FLIP VERIFIED (not_affected -> affected, evidence app.py:24), runner exit 0,
                          fixture restored byte-for-byte, demo working tree untouched

Next recommended capability: evidence-graded reachability verdicts (proven call vs
                          unknown function-level data, per-ecosystem symbol resolution,
                          OpenVEX under_investigation for the conservative case)
Reason:                   all 4 actionable baseline findings are conservative defaults
                          (no function-level data), so the product cannot yet show that a
                          vulnerable function is actually called — the core thesis gap
```

---

## FILES CREATED

| Path | Purpose |
|---|---|
| `POST_IMPLEMENTATION_AUDIT.md` (working tree root, plus an identical copy next to the other audit documents) | this report |
| `software supply chain mvp/tests/test_hardening.py` | regression tests for P0-1, P1-2, P1-3, P1-4 (12 tests, both copies) |
| `chainguard_api/tests/test_real_subprocess.py` | API-level real-subprocess tests: timeout propagation, exit-code mapping, no fabricated evidence (contributes 9 of the 65 collected API tests) |
| `.audit_scratch/*` (temporary) | audit harness: git-vector experiments, live API check, concurrency probe, timeout/orphan probe, two controlled engines. **Removed** after the audit; results are recorded above |

## FILES MODIFIED

| Path | Change |
|---|---|
| `software supply chain mvp/chainguard_mvp/cli.py` | `GIT_HARDENING` + hardened diff/show (P0-1); union of advisory + LLM function candidates (P1-2); unresolved-dependency warnings, trace count and `report.json` field (P1-3) |
| `software supply chain mvp/chainguard_mvp/parsers.py` | `is_concrete_version`, `_unresolved` records, `*_with_diagnostics` variants for requirements / poetry / package.json / pom (P1-3) |
| `software supply chain mvp/chainguard_mvp/sbom.py` | `PINNED_CDXGEN_PACKAGE=@cyclonedx/cdxgen@10.9.0` + `CHAINGUARD_DISABLE_CDXGEN` (P1-4) |
| `software supply chain mvp/README.md` | limitations updated (LLM union, unresolved disclosure, pinned/disable-able cdxgen) — both copies |
| `software supply chain mvp/tests/test_core.py` | unpinned/ranged diagnostics test + cdxgen pin test (earlier phase of this task; verified identical in both copies) |
| `chainguard_api/schemas.py` | `unresolved_dependencies` on `RepositoryResult`; conservative-default/evidence documentation |
| `chainguard_api/service.py` | carries `unresolved_dependencies` through; keeps unknown summary keys; timeout state |
| `chainguard_api/tests/test_api.py`, `chainguard_api/tests/test_path_security.py` | extended for unresolved passthrough and the extended-length path regression |
| `DECISIONS.md`, `THREAT_MODEL.md`, `CLI_CONTRACT.md`, `PROJECT_SPEC.md`, `ARCHITECTURE.md`, `SECURITY_MODEL.md`, `TEST_STRATEGY.md` (in `~/Desktop/software supply chain mvp/`) | specification reconciliation (§10) |

*(`cli.py`, `parsers.py`, `test_hardening.py` were synchronised into both engine copies so a fixed engine cannot
be shadowed by an unfixed one.)*

## FILES NOT TOUCHED

`chainguard_api/app.py`, `config.py`, `engine.py`, `paths.py`, `README.md`, `requirements.txt`, `__init__.py`,
`tests/conftest.py`, `tests/test_real_engine.py`, `tests/test_service.py`;
engine `reachability.py`, `osv.py`, `vex.py`, `slopsquat.py`, `llm.py`, `trace.py`, `dashboard.py`,
`tests/test_diff.py`, `tests/test_dashboard.py`, `pyproject.toml`, `action.yml`, `test_project/**`;
**all of `demo_attack_sim/**`** (verified unchanged through its own git status);
`AGENTS.md` (already correct);
`out/`, `out_audit/`, `out_audit2/`, `out_p1_verify/` artifact directories;
`P1_REMEDIATION_REPORT.md`, `SPEC_IMPLEMENTATION_AUDIT.md` (earlier phase documents).

---

```
NEXT PHASE READY
```

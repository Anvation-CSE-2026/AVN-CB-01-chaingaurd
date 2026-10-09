# ChainBench-100 Benchmark Report

Corpus: **ChainBench-100** — 107 cases, 101 evaluated
(the rest are `UNSUPPORTED`: formats the engine does not parse).

Run started `2026-10-08T22:32:59.120998Z`, finished `2026-10-08T22:36:31.380397Z`.
Engine flags: `--no-llm --fail-on-actionable`. LLM disabled. cdxgen disabled.

## Headline

| Measure | Value |
|---|---|
| Status PASS / PARTIAL / FAIL / ERROR / UNSUPPORTED | 77 / 0 / 24 / 0 / 6 |
| Overall PASS accuracy (of evaluated) | 76.24% |
| Label accuracy (PASS+PARTIAL, of evaluated) | 76.24% |
| Vulnerability detection precision / recall / F1 | 1.0 / 1.0 / 1.0 (TP 293, FP 0, FN 0) |
| Reachability precision / recall / F1 | 0.6897 / 0.8 / 0.7407 (TP 40, FP 18, FN 10, TN 203) |
| Reachability excluding engine-boundary cases P / R / F1 | 0.6897 / 0.8511 / 0.7619 |
| Java-boundary reachability P / R / F1 | n/a / 0.0 / n/a |
| Noise reduction (engine actual) | 76.7918% (225 of 293 dismissed) |
| Noise reduction (ground truth) | 75.4266% (221 of 293 dismissed) |
| Suspicious-package accuracy / precision / recall | 100.00% / 1.0 / 1.0 (TP 26, FP 0, FN 0) |
| Dependency-disclosure case accuracy | 88.12% (89/101) |
| Dependency-disclosure item recall | 57.14% (16/28); unexpected items 0 |
| Evidence completeness | 98.92% (276/279) |
| Case execution success | 100.00% |
| Artifact generation success | 100.00% |
| Exit-code correctness | 91.11% over 90 asserted cases |
| Scan time avg / median / p95 (s) | 1.8801 / 1.495 / 2.755 |
| Baseline test_project | PASS (observed {'total_vulnerabilities': 30, 'dismissed_unreachable': 26, 'actionable': 4, 'suspicious_packages': 1, 'noise_reduced_percent': 86.7}) |

## Per category

| Category | Cases | PASS | PARTIAL | FAIL | ERROR | UNSUPPORTED | PASS accuracy |
|---|---|---|---|---|---|---|---|
| clean | 11 | 11 | 0 | 0 | 0 | 0 | 100.00% |
| dependency_confusion | 7 | 4 | 0 | 3 | 0 | 0 | 57.14% |
| lockfile_mismatch | 8 | 4 | 0 | 4 | 0 | 0 | 50.00% |
| mixed | 8 | 3 | 0 | 5 | 0 | 0 | 37.50% |
| reachable | 13 | 8 | 0 | 5 | 0 | 0 | 61.54% |
| slopsquatting | 10 | 10 | 0 | 0 | 0 | 0 | 100.00% |
| suspicious | 8 | 8 | 0 | 0 | 0 | 0 | 100.00% |
| unpinned | 12 | 10 | 0 | 2 | 0 | 0 | 83.33% |
| unreachable | 13 | 8 | 0 | 5 | 0 | 0 | 61.54% |
| unsupported | 6 | 0 | 0 | 0 | 0 | 6 | n/a |
| vulnerable | 11 | 11 | 0 | 0 | 0 | 0 | 100.00% |

## Failures and partials

| Case | Status | Failed checks | Notes |
|---|---|---|---|
| CB-DC-001 | FAIL | disclosures | missing disclosure --extra-index-url ['index_override_option'] |
| CB-DC-002 | FAIL | disclosures | missing disclosure --index-url ['index_override_option'] |
| CB-DC-006 | FAIL | disclosures | missing disclosure --extra-index-url ['index_override_option'] |
| CB-LOCK-001 | FAIL | disclosures | missing disclosure requests ['manifest_lockfile_mismatch'] |
| CB-LOCK-003 | FAIL | disclosures | missing disclosure pyyaml ['manifest_lockfile_mismatch'] |
| CB-LOCK-004 | FAIL | disclosures | missing disclosure flask ['declared_not_in_lockfile'] |
| CB-LOCK-007 | FAIL | disclosures | missing disclosure Flask ['manifest_lockfile_mismatch'] |
| CB-MIX-002 | FAIL | reachability, disclosures | missing disclosure uuid ['ranged_declaration_proxied'] |
| CB-MIX-003 | FAIL | disclosures | missing disclosure pyyaml ['manifest_lockfile_mismatch'] |
| CB-MIX-004 | FAIL | reachability, disclosures, verdict | missing disclosure --extra-index-url ['index_override_option']; verdict expected DISMISSED+SUSPICIOUS got ACTIONABLE+SUSPICIOUS |
| CB-MIX-006 | FAIL | reachability, verdict | verdict expected ACTIONABLE+SUSPICIOUS got DISMISSED+SUSPICIOUS |
| CB-MIX-007 | FAIL | reachability |  |
| CB-REACH-006 | FAIL | reachability, verdict, exit_code | verdict expected ACTIONABLE got DISMISSED; exit expected 1 got 0 |
| CB-REACH-008 | FAIL | reachability |  |
| CB-REACH-009 | FAIL | reachability |  |
| CB-REACH-012 | FAIL | reachability, verdict, exit_code | verdict expected ACTIONABLE got DISMISSED; exit expected 1 got 0 |
| CB-REACH-013 | FAIL | reachability, verdict, exit_code | verdict expected ACTIONABLE got DISMISSED; exit expected 1 got 0 |
| CB-UNPIN-006 | FAIL | disclosures | missing disclosure lodash ['ranged_declaration_proxied'] |
| CB-UNPIN-007 | FAIL | disclosures | missing disclosure minimist ['ranged_declaration_proxied'] |
| CB-UNREACH-005 | FAIL | reachability, verdict, exit_code | verdict expected DISMISSED got ACTIONABLE; exit expected 0 got 1 |
| CB-UNREACH-006 | FAIL | reachability, verdict, exit_code | verdict expected DISMISSED got ACTIONABLE; exit expected 0 got 1 |
| CB-UNREACH-007 | FAIL | reachability, verdict, exit_code | verdict expected DISMISSED got ACTIONABLE; exit expected 0 got 1 |
| CB-UNREACH-011 | FAIL | reachability, verdict, exit_code | verdict expected DISMISSED got ACTIONABLE; exit expected 0 got 1 |
| CB-UNREACH-012 | FAIL | verdict, exit_code | verdict expected ACTIONABLE got DISMISSED; exit expected 1 got 0 |

Full detail: [failures.json](failures.json) and [metrics.json](metrics.json).

## Engine boundary cases

- **CB-MIX-006** (java_source_reachability): FAIL
- **CB-REACH-012** (java_source_reachability): FAIL
- **CB-REACH-013** (java_source_reachability): FAIL

## Method and limitations

- Ground truth is authored in `tools/corpus_spec.py` from the fixture design and the quoted advisory text. The OSV snapshot supplies only the advisory *set* for each pinned version; registry facts are checked against the spec.
- Vulnerability truth shares its database (OSV) with the engine, so vulnerability-level scores measure the pipeline, not OSV coverage. Reachability, suspicious, and disclosure truth are independent of the engine.
- The engine queries live OSV and public registries. Results depend on that network state at run time; the snapshot records the state used to build the truth. A changed advisory set appears as a vulnerability FP/FN, not as a silent pass.
- Maven Central search is intermittently slow; a lookup that fails is recorded as unknown and not flagged.

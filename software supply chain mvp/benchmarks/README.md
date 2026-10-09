# ChainBench-100

A controlled corpus of 107 small repository fixtures that measures what the
canonical ChainGuard engine (`python -m chainguard_mvp.cli`) actually does. Each
case has independent ground truth, an isolated run, and an evidence check.

The corpus lives here, outside `chainguard_mvp/`. The engine is not modified.

## Layout

```
benchmarks/
  README.md                       this file
  schema/benchmark_case.schema.json   case.json contract
  tools/
    corpus_spec.py                ground truth authored by hand (the source of truth)
    snapshot_sources.py           network: OSV advisories + registry existence -> manifests/source_snapshot.json
    build_corpus.py               offline, deterministic: writes cases/, manifests/ground_truth.json
  cases/<category>/<CASE_ID>/     repo/ (fixture), case.json, README.md
  manifests/
    source_snapshot.json          committed OSV + registry facts used to build the truth
    benchmark_index.json          case index
    ground_truth.json             aggregated ground truth
    benchmark_results.json        latest run (actual engine output vs truth)
  runner/
    run_benchmark.py              executes the engine per case, compares to truth
    score.py                      metrics, failures, report
    README.md                     runner usage
  reports/
    benchmark_report.md           human-readable results
    metrics.json                  all metrics
    failures.json                 every non-PASS case with failed checks
  .runs/<CASE_ID>/                per-case engine output (out-dir isolation)
```

## Reproduce

Run from the project root (`software supply chain mvp/`). Python 3.11, `requests` installed.

```sh
python benchmarks/tools/build_corpus.py        # offline; rebuilds cases/ and manifests/ground_truth.json
python benchmarks/runner/run_benchmark.py      # runs all 107 cases (needs network for OSV/registries)
python benchmarks/runner/score.py              # writes reports/metrics.json, failures.json, benchmark_report.md
```

To refresh the ground-truth snapshot (network), run `python benchmarks/tools/snapshot_sources.py`
and then rebuild. Doing so can change advisory sets and registry facts; the diff is the audit trail.

## Categories

| Category | Cases | Meaning |
|---|---|---|
| clean | 11 | no actionable issue, no disclosure |
| vulnerable | 11 | vulnerable pin, detection only (reachability not asserted) |
| reachable | 13 | vulnerable function called from entry-reachable code |
| unreachable | 13 | vulnerable package unused, or the vulnerable call is not reachable |
| suspicious | 8 | package name absent from its public registry |
| slopsquatting | 10 | typo/hallucinated names (absent), plus established near-name controls |
| dependency_confusion | 7 | internal-looking names and index overrides |
| unpinned | 12 | ranged, wildcard, missing, or malformed declarations |
| lockfile_mismatch | 8 | manifest and lockfile disagree or are incomplete |
| mixed | 8 | several conditions in one fixture |
| unsupported | 6 | formats the engine does not parse (recorded, not scored) |

## Ground truth and scoring

- **Vulnerability truth:** the OSV advisory set for each pinned version (the same
  database the engine uses). Vulnerability scores therefore measure the pipeline,
  not OSV coverage.
- **Reachability truth:** authored from the fixture design and the advisory text quoted in
  `corpus_spec.py ADVISORY_FUNCTIONS`. A finding is REACHABLE only if the entry-reachable
  code calls one of the advisory's named functions. An imported package whose advisory has
  no function data is UNDETERMINED, and the conservative policy expects it to be affected.
- **Suspicious truth:** registry existence recorded in the snapshot (404 = absent).
- **Disclosure truth:** the reasons the spec requires. Some are engine codes; others
  (`index_override_option`, `ranged_declaration_proxied`, `manifest_lockfile_mismatch`,
  `declared_not_in_lockfile`) are benchmark requirements the engine does not implement yet.

Match status: `PASS` (all asserted checks correct, evidence complete), `PARTIAL`
(checks correct, evidence incomplete), `FAIL` (any label check wrong), `ERROR` (run failed),
`UNSUPPORTED` (format outside the parser set; recorded, not scored).

## Limitations

- The engine calls live OSV and public registries. Results depend on network state at run
  time. A changed advisory set appears as a vulnerability FP/FN, not a silent pass.
- Maven Central search is intermittently slow; a failed lookup is recorded as unknown and not flagged.
- Java source is not analysed by the engine. Java reachability cases are marked
  `engine_boundary` and reported separately.
- No package is installed or executed. Fixtures are inert text; the engine parses them.
  `CHAINGUARD_DISABLE_CDXGEN=1` prevents the cdxgen npx download during runs.

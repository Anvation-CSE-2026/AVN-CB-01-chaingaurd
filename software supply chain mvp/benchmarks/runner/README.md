# ChainBench runner

Two scripts, no dependencies beyond `requests` and the standard library.

- `run_benchmark.py` — discovers and validates cases, runs the canonical engine for
  each one, and writes `manifests/benchmark_results.json`.
- `score.py` — reads the results and writes `reports/metrics.json`,
  `reports/failures.json` and `reports/benchmark_report.md`.

## Usage

```sh
python benchmarks/runner/run_benchmark.py                          # all cases + baseline check
python benchmarks/runner/run_benchmark.py --case CB-REACH-001      # subset (writes *.partial.json)
python benchmarks/runner/run_benchmark.py --category reachable
python benchmarks/runner/score.py
```

## What each run does

1. Validates every `case.json` against the required key and type contract.
2. Runs `python -m chainguard_mvp.cli <repo> --no-llm --fail-on-actionable --out-dir benchmarks/.runs/<CASE_ID>`
   with list argv (`shell=False`), from the project root, with a per-run timeout.
   `CHAINGUARD_LLM_*` variables are removed and `CHAINGUARD_DISABLE_CDXGEN=1` is set.
3. Captures stdout, stderr, exit code and wall-clock time.
4. Checks the four artifacts (`report.json`, `trace.json`, `sbom.cdx.json`, `openvex.json`) exist and parse.
5. Compares the actual report to the case's ground truth: vulnerability set, per-finding
   reachability status and justification, suspicious packages, dependency disclosures,
   verdict and exit code, plus evidence for each expected finding.
6. Runs the canonical baseline on `test_project/` and checks it still gives
   30 / 26 / 4 / 1 / 86.7 %.

Engine output is never written into a fixture directory. Each case gets its own
`benchmarks/.runs/<CASE_ID>/` directory.

## Result model

Each record in `benchmark_results.json` carries: `case_id`, `category`, `ecosystem`,
`expected_verdict`, `actual_verdict`, `expected_findings` / `actual_findings`,
`expected_reachability` / `actual_reachability`, `expected_suspicious` / `actual_suspicious`,
`expected_disclosures` / `actual_disclosures`, `exit_code`, `duration_seconds`,
`artifact_status`, `evidence_status`, `match_status`, `checks` and `notes`.

# CB-REACH-001 (reachable)

Direct yaml.full_load call in the entry module.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Direct call of an advisory-named vulnerable function from the entry point.

## Expected call path

`src/app.py:main -> yaml.full_load`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | REACHABLE | affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2020-96 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2021-142 | pyyaml | 5.3 | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-001
```

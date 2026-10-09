# CB-CLEAN-008 (clean)

Vulnerable requests in venv/ must be skipped by discovery.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

venv/ is an environment directory, not a project manifest.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-008
```

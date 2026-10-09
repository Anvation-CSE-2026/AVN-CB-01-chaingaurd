# CB-CLEAN-002 (clean)

Two exact pins with zero advisories (six, click).

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Both pinned versions have zero OSV advisories.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-002
```

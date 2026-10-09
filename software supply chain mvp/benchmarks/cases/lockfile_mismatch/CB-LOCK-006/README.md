# CB-LOCK-006 (lockfile_mismatch)

Lock entry with an empty version string.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

An empty lock version cannot be analysed.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-LOCK-006
```

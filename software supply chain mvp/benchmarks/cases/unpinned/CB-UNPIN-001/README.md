# CB-UNPIN-001 (unpinned)

Lower-bound range requests>=2.19.0.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Ranged declaration must be disclosed.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-001
```

# CB-CLEAN-005 (clean)

Manifest with only comments; nothing to analyse.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

No declarations exist, so the correct result is an empty, clean inventory.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-005
```

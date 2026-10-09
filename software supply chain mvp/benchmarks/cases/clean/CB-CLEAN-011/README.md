# CB-CLEAN-011 (clean)

Environment marker after an exact pin.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

The marker must not corrupt the pinned version.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-011
```

# CB-CLEAN-007 (clean)

Vulnerable lodash vendored under node_modules must be skipped.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

node_modules is dependency output, not the project's declared inventory.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-007
```

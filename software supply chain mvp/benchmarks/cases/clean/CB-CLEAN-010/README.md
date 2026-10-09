# CB-CLEAN-010 (clean)

Clean inventory across PyPI, npm and Maven together.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Three ecosystems, all unaffected.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-010
```

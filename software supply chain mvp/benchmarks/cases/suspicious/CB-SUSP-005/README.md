# CB-SUSP-005 (suspicious)

Ghost npm name with is-number.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Non-existent unscoped npm package.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-005
```

# CB-SUSP-004 (suspicious)

Ghost npm name with a patched chalk pin.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

npm registry returns 404 for the name.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-004
```

# CB-SUSP-006 (suspicious)

Ghost scoped npm package.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Scoped name absent from the public npm registry.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-006
```

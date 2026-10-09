# CB-SUSP-003 (suspicious)

Ghost PyPI name with a click pin.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Hallucinated-style package name.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-003
```

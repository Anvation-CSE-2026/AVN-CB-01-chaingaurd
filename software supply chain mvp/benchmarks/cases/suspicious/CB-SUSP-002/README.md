# CB-SUSP-002 (suspicious)

Ghost PyPI name alongside a legitimate pin.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Ghost is flagged; the legitimate pin is not.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-002
```

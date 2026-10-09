# CB-SUSP-008 (suspicious)

Ghost PyPI name with a patched PyYAML.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Ghost plus a clean legitimate dependency.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-008
```

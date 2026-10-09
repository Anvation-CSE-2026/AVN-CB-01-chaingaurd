# CB-CLEAN-001 (clean)

Exact pin of patched PyYAML 6.0.1 used via safe_load.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

OSV lists zero advisories for pyyaml 6.0.1; the call is not vulnerable.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-001
```

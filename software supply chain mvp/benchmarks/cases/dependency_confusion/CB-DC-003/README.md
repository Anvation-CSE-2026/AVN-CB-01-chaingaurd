# CB-DC-003 (dependency_confusion)

Scoped internal npm name absent from the public registry.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Private-scope name that an attacker could publish publicly.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-003
```

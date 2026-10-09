# CB-DC-001 (dependency_confusion)

Internal name plus --extra-index-url override.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Index override is the classic confusion precondition; it must be disclosed.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-001
```

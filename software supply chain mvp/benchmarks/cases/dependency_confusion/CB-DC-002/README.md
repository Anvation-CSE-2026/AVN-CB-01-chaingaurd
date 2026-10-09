# CB-DC-002 (dependency_confusion)

Internal name with a plain --index-url override.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Primary index replaced; disclose the override and flag the unresolved name.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-002
```

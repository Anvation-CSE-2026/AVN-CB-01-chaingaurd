# CB-DC-006 (dependency_confusion)

Index override in front of an established package.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

The override alone is a disclosable condition even when the package is public.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-006
```

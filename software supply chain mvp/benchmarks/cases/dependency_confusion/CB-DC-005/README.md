# CB-DC-005 (dependency_confusion)

CONTROL: established public name, no index override.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

An established public package is not a confusion precondition by itself.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-005
```

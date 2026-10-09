# CB-DC-004 (dependency_confusion)

Internal Maven coordinate absent from Maven Central.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Internal groupId with no public artifact.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-004
```

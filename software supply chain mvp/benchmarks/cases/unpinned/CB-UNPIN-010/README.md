# CB-UNPIN-010 (unpinned)

Maven version is an unresolved property.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Property placeholders cannot be resolved without a parent POM.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-010
```

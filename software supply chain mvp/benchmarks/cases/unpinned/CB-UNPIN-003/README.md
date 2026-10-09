# CB-UNPIN-003 (unpinned)

Wildcard pin requests==2.*.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

A wildcard is not an exact version.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-003
```

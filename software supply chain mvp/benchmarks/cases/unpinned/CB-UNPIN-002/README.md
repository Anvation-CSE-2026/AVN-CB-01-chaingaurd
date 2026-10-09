# CB-UNPIN-002 (unpinned)

Bare name with no version (flask).

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

No version at all is unresolvable.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-002
```

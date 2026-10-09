# CB-UNPIN-011 (unpinned)

Maven dependency with no version element.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Version may come from dependencyManagement; it must still be disclosed.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-011
```

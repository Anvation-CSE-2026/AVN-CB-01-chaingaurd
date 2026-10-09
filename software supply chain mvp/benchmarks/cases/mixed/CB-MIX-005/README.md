# CB-MIX-005 (mixed)

Ghost typo plus clean pin plus ranged dependency.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Suspicious-only verdict with an unpinned disclosure.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-005
```

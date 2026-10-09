# CB-SLOP-004 (slopsquatting)

Typo of numpy (numpyy).

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Doubled-letter typosquat.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-004
```

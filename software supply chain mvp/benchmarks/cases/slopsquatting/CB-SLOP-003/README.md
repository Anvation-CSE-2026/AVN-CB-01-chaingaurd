# CB-SLOP-003 (slopsquatting)

Typo of flask (flaskk).

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Doubled-letter typosquat.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-003
```

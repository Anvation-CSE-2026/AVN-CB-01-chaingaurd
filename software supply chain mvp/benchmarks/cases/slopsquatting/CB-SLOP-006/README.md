# CB-SLOP-006 (slopsquatting)

Hallucinated npm helper (axios-retry-helpers-plus).

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Plausible-sounding helper that does not exist on npm.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-006
```

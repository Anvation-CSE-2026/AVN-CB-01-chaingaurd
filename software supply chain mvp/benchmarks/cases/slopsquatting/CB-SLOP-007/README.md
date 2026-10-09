# CB-SLOP-007 (slopsquatting)

Typo of beautifulsoup4 (beautifulsoup5).

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Version-number suffix squat; absent on PyPI.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-007
```

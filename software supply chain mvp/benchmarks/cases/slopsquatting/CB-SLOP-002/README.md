# CB-SLOP-002 (slopsquatting)

Typo of pyyaml (pyyamll).

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Doubled-letter typosquat; absent on PyPI.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-002
```

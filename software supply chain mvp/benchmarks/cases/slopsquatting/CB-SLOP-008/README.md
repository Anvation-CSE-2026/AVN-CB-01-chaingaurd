# CB-SLOP-008 (slopsquatting)

Hallucinated PyPI name with an -x suffix.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Plausible combination of two real project names.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-008
```

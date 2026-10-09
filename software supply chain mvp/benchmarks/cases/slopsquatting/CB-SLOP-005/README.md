# CB-SLOP-005 (slopsquatting)

Typo of urllib3 (urlib3x).

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Dropped letter plus suffix.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-005
```

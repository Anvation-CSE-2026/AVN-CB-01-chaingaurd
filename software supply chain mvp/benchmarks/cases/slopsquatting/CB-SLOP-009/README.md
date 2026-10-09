# CB-SLOP-009 (slopsquatting)

CONTROL: boto is near boto3 but established on PyPI.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Name similarity alone must not flag an established package with many releases.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-009
```

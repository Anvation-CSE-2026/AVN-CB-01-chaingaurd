# CB-SLOP-001 (slopsquatting)

Typo of requests (reqeusts) in requirements.txt.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Transposed-letter typosquat of a popular package; absent on PyPI.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-001
```

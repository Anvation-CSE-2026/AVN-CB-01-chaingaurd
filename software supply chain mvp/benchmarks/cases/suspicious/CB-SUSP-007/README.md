# CB-SUSP-007 (suspicious)

Ghost Maven artifact next to guava 33.3.1-jre.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Maven Central search returns zero artifacts for the coordinate.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-007
```

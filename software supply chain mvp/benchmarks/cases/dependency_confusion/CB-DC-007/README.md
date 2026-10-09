# CB-DC-007 (dependency_confusion)

Internal-looking npm name chalk-internal-logger.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Name resembles a real package family but is absent from npm.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-DC-007
```

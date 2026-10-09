# CB-SUSP-001 (suspicious)

Ghost PyPI name pinned in requirements.txt.

- **Expected verdict:** `SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Name does not exist on PyPI (HTTP 404 in the snapshot).

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SUSP-001
```

# CB-REACH-006 (reachable)

Function passed by reference to map() and invoked.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

A reference that is executed is reachable; an AST call-only check misses it.

## Expected call path

`src/app.py:load_all -> map(yaml.full_load) invokes the function`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | REACHABLE | affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2020-96 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2021-142 | pyyaml | 5.3 | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-006
```

# CB-UNREACH-012 (unreachable)

minimist imported but never called.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Reference without invocation is not a call.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-vh95-rmgr-6w4m | minimist | 1.2.0 | UNREACHABLE | not_affected |
| GHSA-xvch-5gv4-984h | minimist | 1.2.0 | UNDETERMINED | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNREACH-012
```

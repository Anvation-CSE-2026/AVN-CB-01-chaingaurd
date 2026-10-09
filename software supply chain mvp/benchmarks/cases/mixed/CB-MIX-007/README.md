# CB-MIX-007 (mixed)

Dead template call and reachable omit in one lodash project.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Per-advisory truth: omit-based advisories reachable; template only in dead code.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-29mw-wpgm-hmr9 | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-35jh-r3h4-6jhm | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-f23m-r3pf-42rh | lodash | 4.17.15 | REACHABLE | affected |
| GHSA-p6mc-m468-83gw | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-r5fr-rjxr-66jc | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-xxjr-mmjv-4gpg | lodash | 4.17.15 | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-007
```

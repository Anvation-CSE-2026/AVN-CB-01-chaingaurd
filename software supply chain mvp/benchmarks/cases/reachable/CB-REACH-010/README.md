# CB-REACH-010 (reachable)

_.omit reached: unset/omit advisories reachable, template not.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Mixed per-advisory truth inside one package: only unset/omit advisories are reachable.

## Expected call path

`index.js -> _.omit`

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
python benchmarks/runner/run_benchmark.py --case CB-REACH-010
```

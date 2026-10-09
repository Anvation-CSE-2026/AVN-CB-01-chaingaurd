# CB-MIX-002 (mixed)

JS: reachable template, dismissed minimist, ghost, caret proxy.

- **Expected verdict:** `ACTIONABLE+SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Combines a reachable call the engine should not miss with independent conditions.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-29mw-wpgm-hmr9 | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-35jh-r3h4-6jhm | lodash | 4.17.15 | REACHABLE | affected |
| GHSA-f23m-r3pf-42rh | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-p6mc-m468-83gw | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-r5fr-rjxr-66jc | lodash | 4.17.15 | REACHABLE | affected |
| GHSA-xxjr-mmjv-4gpg | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-vh95-rmgr-6w4m | minimist | 1.2.0 | UNREACHABLE | not_affected |
| GHSA-xvch-5gv4-984h | minimist | 1.2.0 | UNREACHABLE | not_affected |
| GHSA-w5hq-g745-h8pq | uuid | 9.0.1 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-002
```

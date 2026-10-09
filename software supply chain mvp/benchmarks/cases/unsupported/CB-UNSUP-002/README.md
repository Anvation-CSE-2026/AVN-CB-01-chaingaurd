# CB-UNSUP-002 (unsupported)

package-lock.json as the only npm inventory.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** False
- **Engine boundary probed:** none

## Rationale

package-lock.json is not in the supported set; the engine sees nothing.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-29mw-wpgm-hmr9 | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-35jh-r3h4-6jhm | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-f23m-r3pf-42rh | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-p6mc-m468-83gw | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-r5fr-rjxr-66jc | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-xxjr-mmjv-4gpg | lodash | 4.17.15 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNSUP-002
```

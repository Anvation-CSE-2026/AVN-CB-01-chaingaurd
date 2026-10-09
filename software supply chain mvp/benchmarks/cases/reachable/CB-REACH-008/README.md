# CB-REACH-008 (reachable)

lodash _.template reached from index.js via server.js.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

GHSA-35jh 'via the template function' is reached; the engine's extractor is expected to miss it.

## Expected call path

`index.js -> server.js:render -> _.template`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-29mw-wpgm-hmr9 | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-35jh-r3h4-6jhm | lodash | 4.17.15 | REACHABLE | affected |
| GHSA-f23m-r3pf-42rh | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-p6mc-m468-83gw | lodash | 4.17.15 | UNREACHABLE | not_affected |
| GHSA-r5fr-rjxr-66jc | lodash | 4.17.15 | REACHABLE | affected |
| GHSA-xxjr-mmjv-4gpg | lodash | 4.17.15 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-008
```

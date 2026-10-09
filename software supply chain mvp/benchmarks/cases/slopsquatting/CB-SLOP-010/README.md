# CB-SLOP-010 (slopsquatting)

CONTROL: lodash-es is close to lodash but established on npm.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Established near-name control; the registry record is not suspicious.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-f23m-r3pf-42rh | lodash-es | 4.17.21 | UNREACHABLE | not_affected |
| GHSA-r5fr-rjxr-66jc | lodash-es | 4.17.21 | UNREACHABLE | not_affected |
| GHSA-xxjr-mmjv-4gpg | lodash-es | 4.17.21 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-SLOP-010
```

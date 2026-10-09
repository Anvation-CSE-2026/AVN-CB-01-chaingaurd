# CB-VULN-008 (vulnerable)

minimist 1.2.0 declared only.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Two advisories for minimist 1.2.0.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-vh95-rmgr-6w4m | minimist | 1.2.0 | UNREACHABLE | not_affected |
| GHSA-xvch-5gv4-984h | minimist | 1.2.0 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-VULN-008
```

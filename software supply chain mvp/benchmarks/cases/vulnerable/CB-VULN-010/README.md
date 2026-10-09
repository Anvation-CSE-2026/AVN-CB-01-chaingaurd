# CB-VULN-010 (vulnerable)

requests 2.32.4 declared and not patched to the latest.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Four advisories for requests 2.32.4.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-gc5v-m9x4-r6x2 | requests | 2.32.4 | UNREACHABLE | not_affected |
| PYSEC-2026-2275 | requests | 2.32.4 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-VULN-010
```

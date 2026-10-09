# CB-VULN-001 (vulnerable)

requests 2.19.0 declared but never imported.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Detection of a declared vulnerable pin.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-9hjg-9r4m-mvj7 | requests | 2.19.0 | UNREACHABLE | not_affected |
| GHSA-9wx4-h78v-vm56 | requests | 2.19.0 | UNREACHABLE | not_affected |
| GHSA-gc5v-m9x4-r6x2 | requests | 2.19.0 | UNREACHABLE | not_affected |
| GHSA-j8r2-6x86-q33q | requests | 2.19.0 | UNREACHABLE | not_affected |
| GHSA-x84v-xcm2-53pg | requests | 2.19.0 | UNREACHABLE | not_affected |
| PYSEC-2018-28 | requests | 2.19.0 | UNREACHABLE | not_affected |
| PYSEC-2023-74 | requests | 2.19.0 | UNREACHABLE | not_affected |
| PYSEC-2026-1872 | requests | 2.19.0 | UNREACHABLE | not_affected |
| PYSEC-2026-1873 | requests | 2.19.0 | UNREACHABLE | not_affected |
| PYSEC-2026-2275 | requests | 2.19.0 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-VULN-001
```

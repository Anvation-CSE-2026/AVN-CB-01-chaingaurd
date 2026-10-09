# CB-LOCK-001 (lockfile_mismatch)

requirements pins 2.19.0; poetry.lock resolves 2.32.4.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Two versions of one package disagree; the disagreement must be disclosed.

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
| GHSA-gc5v-m9x4-r6x2 | requests | 2.32.4 | UNREACHABLE | not_affected |
| PYSEC-2026-2275 | requests | 2.32.4 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-LOCK-001
```

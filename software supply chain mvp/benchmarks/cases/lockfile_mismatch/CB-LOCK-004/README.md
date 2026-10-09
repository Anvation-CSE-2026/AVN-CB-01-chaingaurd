# CB-LOCK-004 (lockfile_mismatch)

flask pinned in requirements, absent from poetry.lock.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

A declared dependency that the lock does not resolve is a disclosable inconsistency.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-562c-5r94-xh97 | flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-5wv5-4vpf-pj6m | flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-68rp-wp8r-4726 | flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-m2qf-hxjv-5gpq | flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2018-66 | flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2019-179 | flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2023-62 | flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2026-2151 | flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-gc5v-m9x4-r6x2 | requests | 2.32.4 | UNREACHABLE | not_affected |
| PYSEC-2026-2275 | requests | 2.32.4 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-LOCK-004
```

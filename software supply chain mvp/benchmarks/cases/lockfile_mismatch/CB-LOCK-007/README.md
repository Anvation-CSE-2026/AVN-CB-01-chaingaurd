# CB-LOCK-007 (lockfile_mismatch)

Flask 0.12 pinned; lock resolves flask 2.3.3 (case differs).

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Different versions under a case-insensitive name must be treated as a mismatch.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-562c-5r94-xh97 | Flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-5wv5-4vpf-pj6m | Flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-68rp-wp8r-4726 | Flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-m2qf-hxjv-5gpq | Flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2018-66 | Flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2019-179 | Flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2023-62 | Flask | 0.12 | UNREACHABLE | not_affected |
| PYSEC-2026-2151 | Flask | 0.12 | UNREACHABLE | not_affected |
| GHSA-68rp-wp8r-4726 | flask | 2.3.3 | UNREACHABLE | not_affected |
| PYSEC-2026-2151 | flask | 2.3.3 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-LOCK-007
```

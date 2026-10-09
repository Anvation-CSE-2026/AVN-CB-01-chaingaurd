# CB-VULN-005 (vulnerable)

Flask 0.12 declared only (many advisories).

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Multi-advisory detection under a capitalised name.

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

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-VULN-005
```

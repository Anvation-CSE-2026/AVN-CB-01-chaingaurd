# CB-MIX-001 (mixed)

Actionable + unreachable + ghost + unpinned in one Python repo.

- **Expected verdict:** `ACTIONABLE+SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Each condition is present and must be reported independently.

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
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | REACHABLE | affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2020-96 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2021-142 | pyyaml | 5.3 | REACHABLE | affected |
| GHSA-9hjg-9r4m-mvj7 | requests | 2.19.0 | UNDETERMINED | affected |
| GHSA-9wx4-h78v-vm56 | requests | 2.19.0 | UNDETERMINED | affected |
| GHSA-gc5v-m9x4-r6x2 | requests | 2.19.0 | UNDETERMINED | affected |
| GHSA-j8r2-6x86-q33q | requests | 2.19.0 | UNDETERMINED | affected |
| GHSA-x84v-xcm2-53pg | requests | 2.19.0 | UNDETERMINED | affected |
| PYSEC-2018-28 | requests | 2.19.0 | UNDETERMINED | affected |
| PYSEC-2023-74 | requests | 2.19.0 | UNDETERMINED | affected |
| PYSEC-2026-1872 | requests | 2.19.0 | UNDETERMINED | affected |
| PYSEC-2026-1873 | requests | 2.19.0 | UNDETERMINED | affected |
| PYSEC-2026-2275 | requests | 2.19.0 | UNDETERMINED | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-001
```

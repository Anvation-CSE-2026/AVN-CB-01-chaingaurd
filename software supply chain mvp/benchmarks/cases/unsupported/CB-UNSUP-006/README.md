# CB-UNSUP-006 (unsupported)

Pipenv Pipfile.lock with requests 2.19.0.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** False
- **Engine boundary probed:** none

## Rationale

Pipfile.lock is not parsed, so the pinned vulnerable version is missed.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
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
python benchmarks/runner/run_benchmark.py --case CB-UNSUP-006
```

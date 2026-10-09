# CB-LOCK-002 (lockfile_mismatch)

poetry.lock only (lockfile-only resolution).

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

A vulnerable lock entry with no manifest must still be analysed.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | UNREACHABLE | not_affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | UNREACHABLE | not_affected |
| PYSEC-2020-96 | pyyaml | 5.3 | UNREACHABLE | not_affected |
| PYSEC-2021-142 | pyyaml | 5.3 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-LOCK-002
```

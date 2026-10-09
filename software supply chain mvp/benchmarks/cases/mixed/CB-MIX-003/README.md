# CB-MIX-003 (mixed)

Reachable full_load plus a manifest/lock version mismatch.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Reachable vulnerability and a lockfile disagreement at once.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | REACHABLE | affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2020-96 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2021-142 | pyyaml | 5.3 | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-003
```

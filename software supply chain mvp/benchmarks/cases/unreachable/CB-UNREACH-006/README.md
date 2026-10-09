# CB-UNREACH-006 (unreachable)

yaml.full_load only in a dead function never invoked.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Call exists in source but is not reachable from the entry point.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | UNREACHABLE | not_affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | UNREACHABLE | not_affected |
| PYSEC-2020-96 | pyyaml | 5.3 | UNREACHABLE | not_affected |
| PYSEC-2021-142 | pyyaml | 5.3 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNREACH-006
```

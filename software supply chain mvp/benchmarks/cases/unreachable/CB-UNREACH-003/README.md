# CB-UNREACH-003 (unreachable)

json.load (control) plus yaml.dump; no vulnerable call.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

A 'load' name on another module must not be attributed to yaml.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | UNREACHABLE | not_affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | UNREACHABLE | not_affected |
| PYSEC-2020-96 | pyyaml | 5.3 | UNREACHABLE | not_affected |
| PYSEC-2021-142 | pyyaml | 5.3 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNREACH-003
```

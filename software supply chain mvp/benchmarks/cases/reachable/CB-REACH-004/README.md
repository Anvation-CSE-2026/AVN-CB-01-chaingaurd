# CB-REACH-004 (reachable)

Cross-module call: main -> config -> yaml.full_load.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Reachability across modules must be found.

## Expected call path

`src/main.py -> src/config.py:load_config -> yaml.full_load`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-6757-jp84-gxfx | pyyaml | 5.3 | REACHABLE | affected |
| GHSA-8q59-q68h-6hv4 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2020-96 | pyyaml | 5.3 | REACHABLE | affected |
| PYSEC-2021-142 | pyyaml | 5.3 | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-004
```

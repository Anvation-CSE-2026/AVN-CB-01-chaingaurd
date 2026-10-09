# CB-MIX-008 (mixed)

Discovery trap: venv, node_modules, clean pin and unpinned line.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Skipped directories must not contribute findings while the real unpinned line is disclosed.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-008
```

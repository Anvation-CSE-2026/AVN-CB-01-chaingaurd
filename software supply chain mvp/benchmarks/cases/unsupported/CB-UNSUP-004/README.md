# CB-UNSUP-004 (unsupported)

Go module (go.mod) with a pinned websocket.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** False
- **Engine boundary probed:** none

## Rationale

No go.mod parser; not measured.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNSUP-004
```

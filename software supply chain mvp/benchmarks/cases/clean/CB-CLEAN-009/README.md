# CB-CLEAN-009 (clean)

Exact pin with spaces around == and an inline comment.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Whitespace and comments around an exact pin must still parse as a pin.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-009
```

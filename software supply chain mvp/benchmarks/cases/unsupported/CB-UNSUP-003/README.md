# CB-UNSUP-003 (unsupported)

Rust Cargo.toml (crates.io) with a pinned crate.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** False
- **Engine boundary probed:** none

## Rationale

No Cargo parser exists; vulnerability truth is not measured for this ecosystem.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNSUP-003
```

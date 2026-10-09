# CB-UNPIN-008 (unpinned)

npm 'latest' dist-tag.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

A dist-tag is not a version.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-008
```

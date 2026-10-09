# CB-CLEAN-006 (clean)

package.json with empty dependency sections.

- **Expected verdict:** `CLEAN` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Empty sections must not produce findings or disclosures.

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-CLEAN-006
```

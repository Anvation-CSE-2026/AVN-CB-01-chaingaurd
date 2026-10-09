# CB-UNPIN-007 (unpinned)

npm tilde range ~1.2.0 analysed as its lower bound.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Same silent lower-bound proxy as the caret case.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-vh95-rmgr-6w4m | minimist | 1.2.0 | UNREACHABLE | not_affected |
| GHSA-xvch-5gv4-984h | minimist | 1.2.0 | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNPIN-007
```

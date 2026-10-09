# CB-REACH-011 (reachable)

minimist(argv) called directly from the entry script.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

GHSA-vh95 is reachable; the second advisory has no function data (conservative).

## Expected call path

`index.js -> minimist(process.argv)`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-vh95-rmgr-6w4m | minimist | 1.2.0 | REACHABLE | affected |
| GHSA-xvch-5gv4-984h | minimist | 1.2.0 | UNDETERMINED | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-011
```

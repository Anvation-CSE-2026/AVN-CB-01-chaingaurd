# CB-REACH-013 (reachable)

Guava Files.createTempDir() called from Java source.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** java_source_reachability

## Rationale

Ground truth is reachable. Java reachability is outside the engine's analysis.

## Expected call path

`src/main/java/app/App.java:dir -> Files.createTempDir`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-5mg8-w23w-74h3 | com.google.guava:guava | 31.1-jre | REACHABLE | affected |
| GHSA-7g45-4rm6-3mm3 | com.google.guava:guava | 31.1-jre | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-013
```

# CB-REACH-012 (reachable)

Guava FileBackedOutputStream constructed in Java source.

- **Expected verdict:** `ACTIONABLE` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** java_source_reachability

## Rationale

Ground truth is reachable. The engine does not parse .java, so this probes a stated boundary.

## Expected call path

`src/main/java/app/App.java:open -> FileBackedOutputStream`

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-5mg8-w23w-74h3 | com.google.guava:guava | 31.1-jre | UNREACHABLE | not_affected |
| GHSA-7g45-4rm6-3mm3 | com.google.guava:guava | 31.1-jre | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-REACH-012
```

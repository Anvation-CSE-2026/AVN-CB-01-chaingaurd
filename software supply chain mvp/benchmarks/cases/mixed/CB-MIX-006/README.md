# CB-MIX-006 (mixed)

Java reachable guava + ghost + unresolved property (boundary).

- **Expected verdict:** `ACTIONABLE+SUSPICIOUS` (exit `1`)
- **Supported by engine:** True
- **Engine boundary probed:** java_source_reachability

## Rationale

Java reachability is a stated engine boundary; the other conditions are native.

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-5mg8-w23w-74h3 | com.google.guava:guava | 31.1-jre | UNREACHABLE | not_affected |
| GHSA-7g45-4rm6-3mm3 | com.google.guava:guava | 31.1-jre | REACHABLE | affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-MIX-006
```

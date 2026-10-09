# CB-UNREACH-013 (unreachable)

Guava declared; Java app does not import it.

- **Expected verdict:** `DISMISSED` (exit `0`)
- **Supported by engine:** True
- **Engine boundary probed:** none

## Rationale

Declared but not used by the application (no Java-import analysis is needed here).

## Ground-truth advisories

| advisory | package | version | label | expected status |
|---|---|---|---|---|
| GHSA-5mg8-w23w-74h3 | com.google.guava:guava | 31.1-jre | UNREACHABLE | not_affected |
| GHSA-7g45-4rm6-3mm3 | com.google.guava:guava | 31.1-jre | UNREACHABLE | not_affected |

## Reproduce

```sh
python benchmarks/runner/run_benchmark.py --case CB-UNREACH-013
```

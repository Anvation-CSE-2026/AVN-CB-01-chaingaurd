# ChainGuard API — horizontal (fleet) scanning layer

FastAPI service that drives the **real** ChainGuard engine
(`software supply chain mvp/chainguard_mvp`) as a subprocess. The engine is
never modified, never mocked in production, and never replaced by a stub.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -r requirements.txt

uvicorn chainguard_api.app:app --host 127.0.0.1 --port 8010   # from the workspace root
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | engine availability (`ok` / `degraded` + real path/entrypoint) and the configured node |
| GET | `/remote` | read-only preflight of the remote node (see [BRIDGE_CLIENT_CONTRACT.md](BRIDGE_CLIENT_CONTRACT.md)) |
| POST | `/scan` | scan one repository with the real CLI, locally or on the node |
| POST | `/scan/fleet` | scan N repositories with bounded concurrency |

```json
POST /scan
{"repository": {"id": "repo-001", "path": "/allowed/root/project"}}
```

Every result carries a provenance block, so which machine ran the scan is never
implied:

```json
"execution": {"mode": "local", "node": null, "artifacts_remote": false}
```

```json
POST /scan/fleet
{"repositories": [{"id": "repo-a", "path": "/allowed/root/repo-a"},
                  {"id": "repo-b", "path": "/allowed/root/repo-b"}]}
```

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `CHAIN_GUARD_ENGINE_ROOT` | `<workspace>/software supply chain mvp` | directory containing `chainguard_mvp/` |
| `CHAIN_GUARD_ALLOWED_ROOT` | `<workspace>` | repositories must resolve inside this root |
| `CHAIN_GUARD_SCAN_WORKSPACE` | `<chainguard_api>/scan_workspace` | isolated outputs (`<scan-id>/<repo-id>/`) |
| `MAX_CONCURRENT_SCANS` | `2` | bounded worker pool |
| `SCAN_TIMEOUT_SECONDS` | `300` | per-repository subprocess timeout |
| `CHAIN_GUARD_PYTHON` | current interpreter | interpreter used to run the engine |
| `CHAIN_GUARD_NO_LLM` | `true` | pass `--no-llm` |

### Remote execution (**gated off by default**)

Remote execution is a prepared but unopened capability. With the gate closed and
none of these set, the service behaves exactly as before: every scan runs here
and no entry point can open a connection to a node. See
[BRIDGE_CLIENT_CONTRACT.md](BRIDGE_CLIENT_CONTRACT.md) for the topology, both
contracts, the error states and what is deliberately not implemented yet.

| Variable | Default | Meaning |
|---|---|---|
| `CHAIN_GUARD_EXECUTION_MODE` | `local` | default mode for a scan that does not choose one (`local` or `remote`) |
| `CHAIN_GUARD_REMOTE_ENABLED` | `false` | **the gate.** Empty is not true; nothing leaves this machine until it is explicitly enabled |
| `CHAIN_GUARD_REMOTE_URL` | *(unset)* | base URL of the node; required once the gate is open |
| `CHAIN_GUARD_REMOTE_TOKEN` | *(unset)* | bearer token sent to the node |
| `CHAIN_GUARD_REMOTE_TOKEN_FILE` | *(unset)* | file holding the token (one trailing newline ignored) |
| `CHAIN_GUARD_REMOTE_TIMEOUT_SECONDS` | `300` | per-scan round-trip budget |
| `CHAIN_GUARD_REMOTE_HEALTH_TIMEOUT_SECONDS` | `10` | preflight probe budget |
| `CHAIN_GUARD_REMOTE_ALLOWED_ROOT` | *(unset)* | repository paths must sit under this prefix **as the node sees it** |
| `CHAIN_GUARD_REMOTE_LABEL` | host:port | display name for the node in responses |

No developer-specific absolute path is hard-coded anywhere; the defaults are
derived relative to this package.

**Important:** the interpreter that runs the engine must have `requests`
(the engine's only declared dependency) installed, otherwise OSV lookups
silently return nothing. `/health` explicitly verifies this and reports
`degraded` rather than `ok`.

## Public deployment (access token)

With no token configured the API behaves exactly as before (open, for local use).
Before it is reachable by anyone else, set a token:

| Variable | Default | Meaning |
|---|---|---|
| `CHAIN_GUARD_API_TOKEN` | *(unset)* | when set, `/scan`, `/scan/fleet`, `/scans/...` (artifacts) and `/remote` require `Authorization: Bearer <token>`. Compared in constant time. |
| `CHAIN_GUARD_API_TOKEN_FILE` | *(unset)* | same, read from a file. An unreadable or empty file stops startup rather than opening the service. |
| `CHAIN_GUARD_MAX_REQUEST_BYTES` | `65536` | request bodies above this size are refused with 413 before any route runs |

When a token is set: `/health` returns only `status` and engine readiness to
anonymous callers (no engine path, no remote node); `/docs`, `/redoc` and
`/openapi.json` are not served; `/` and the dashboard at `/ui` stay public
because they contain no credential. CORS is not enabled, so browsers refuse
cross-origin reads of the API. The dashboard keeps the token in memory only
(Settings page), so it must be entered again after a reload.

A Render blueprint is in [`../render.yaml`](../render.yaml). It sets
`CHAIN_GUARD_ALLOWED_ROOT` to the checkout, keeps remote execution disabled, and
health-checks `/health`. The Mac node is never exposed by it.

## Exit-code mapping (real scanner)

| scanner exit | API state | API status |
|---|---|---|
| 0 | `COMPLETED` | `completed` |
| 1 (`--fail-on-actionable`) | `ACTIONABLE` | `completed` |
| 2 | `INVALID_INPUT` | `failed` (`SCAN_INVALID_INPUT`) |
| other | `ENGINE_ERROR` | `failed` (`SCAN_FAILED`) |
| timeout | `TIMEOUT` | `timeout` (`SCAN_TIMEOUT`) |

## Remote failure codes

A scan requested with `"execution_mode": "remote"` can fail on this side of the
bridge. Each code has exactly one HTTP answer, defined in
[`remote.py`](remote.py) (`FAILURE_MAP`) and covered by tests.

| Code | HTTP | Meaning |
|---|---|---|
| `REMOTE_EXECUTION_DISABLED` | 503 | the gate is closed (the default) — never retried locally |
| `REMOTE_EXECUTION_NOT_CONFIGURED` | 503 | gate open but `CHAIN_GUARD_REMOTE_URL` is unset — never retried locally |
| `REMOTE_CLIENT_UNAVAILABLE` | 503 | `httpx` is missing in this interpreter (local scans are unaffected) |
| `REMOTE_PATH_NOT_ALLOWED` | 400 | the remote path is relative, NUL-bearing, or outside the declared root |
| `REMOTE_REQUEST_REJECTED` | 400 | the node rejected the request (bad path or body) |
| `REMOTE_TIMEOUT` | 504 | the node did not answer in time (`state: TIMEOUT`, `status: timeout`) |
| `REMOTE_UNREACHABLE` | 502 | the node could not be reached at all |
| `REMOTE_AUTH_REJECTED` | 502 | the node rejected our token |
| `REMOTE_ENGINE_UNAVAILABLE` | 503 | the node's own engine is not runnable |
| `REMOTE_INVALID_RESPONSE` | 502 | the node's reply does not match the canonical result contract |
| `REMOTE_HTTP_ERROR` | 502 | any other unexpected answer (including a redirect) |

Fleet status: `completed` (all scans produced reports), `partial` (some),
`failed` (none). Fleet totals are strict sums of the per-repository summaries.

## Tests

```bash
.venv/Scripts/python.exe -m pytest chainguard_api/tests -q
```

`tests/test_real_engine.py` invokes the real scanner against
`software supply chain mvp/test_project` (no mocks) and asserts the API
exposes the same result as `report.json` on disk.
`tests/test_remote.py` covers the node contract and the remote path against a
stand-in node on an in-process HTTP transport, including the branches that must
fail closed (gate closed, enabled but unconfigured, path outside the declared
root, malformed reply, timeout, redirect). It also asserts the strongest
invariant of the prepared-not-enabled state: with the gate closed, no entry
point — `/health`, `/remote`, local `/scan`, local `/scan/fleet` or the CLI —
constructs an HTTP client at all.

## Notes

- `demo_attack_sim/` is not touched by this service.
- Outputs are written only under `scan_workspace/` (git-ignored).

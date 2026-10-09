# BRIDGE_CLIENT_CONTRACT.md — ChainGuard remote-execution client contract

**Version:** 1.0.0 · **Status:** contract prepared, transport **gated off** · **Layer:** 2 (API / coordinator)

This document defines how this laptop prepares to drive a ChainGuard engine that
runs on another machine, and what is deliberately *not* implemented yet. It is
the client half of the architecture: the node half is an unmodified ChainGuard
API, defined by `INTEGRATION_CONTRACT.md`.

---

## 1. Purpose

Keep the security engine on one machine and optionally execute scans on another,
**without merging the two codebases**. This laptop stays a complete, working
local deployment; the future bridge is an interface between two independent
deployments, not a shared filesystem or a copied scanner.

Target architecture:

```text
THIS MACHINE (coordinator)                    THE NODE (executor)
──────────────────────────                    ───────────────────
frontend/            dashboard at /ui         (no dashboard needed)
chainguard_api/      coordinator              chainguard_api/  (same service)
chainguard_mvp/      local engine (optional)  chainguard_mvp/  (required)
        │                                             ▲
        │   POST /scan  execution_mode: remote        │
        └─────────────────────────────────────────────┘
                    (gated off by default)
```

## 2. Local execution (the default, and the current state)

Unchanged in every respect:

- `POST /scan` runs `python -m chainguard_mvp.cli <target> --out-dir <dir> --no-llm`
  as an argument array with `shell=False`, bounded by `MAX_CONCURRENT_SCANS` and
  `SCAN_TIMEOUT_SECONDS`.
- The response is the canonical `RepositoryResult` with
  `execution: {"mode": "local", "artifacts_remote": false}` and all four artifact
  paths present on this machine.
- No configuration in this document affects a local scan. With the remote
  settings unset, the service behaves exactly as it did before they existed.

The engine remains the sole source of security truth. Nothing in the remote path
computes, adjusts or re-verifies a verdict.

## 3. Remote execution (prepared, disabled)

Two independent facts must both hold before a single byte leaves this machine:

| Fact | Variable | Default |
|---|---|---|
| the gate is open | `CHAIN_GUARD_REMOTE_ENABLED` | **false** |
| a node is named | `CHAIN_GUARD_REMOTE_URL` | *(unset)* |

`configured` means both. **While the gate is closed, no entry point of this
service can open a network connection to a node**, and the capability is
reported as unavailable rather than silently substituted:

- a scan asking for `execution_mode: remote` fails with `REMOTE_EXECUTION_DISABLED`
  (HTTP 503) — never quietly executed locally;
- `GET /remote` (the preflight) reports the closed gate and probes nothing;
- `python -m chainguard_api.remote_check` reports the closed gate and probes
  nothing unless `--enable` (or the environment gate) is given;
- `GET /health` discloses the state without contacting anything.

Opening the gate is a deliberate, explicit act. Everything below then applies.

### Request

```json
POST /scan
{
  "repository": {"id": "repo-001", "path": "<path on the node>"},
  "options": {"no_llm": true, "fail_on_actionable": false, "dashboard": false,
              "diff_ref": null, "execution_mode": "remote"}
}
```

`execution_mode` is optional per request; `CHAIN_GUARD_EXECUTION_MODE` sets the
deployment default (`local`). An unrecognised value falls back to `local`, so a
typo can never make the service claim a scan ran somewhere it did not.

`repository.path` is a path **as the node sees it**. The coordinator normalises
it (separators, `..`, NUL, absolute-ness) and enforces
`CHAIN_GUARD_REMOTE_ALLOWED_ROOT` if set; the node then applies its own
`CHAIN_GUARD_ALLOWED_ROOT` containment. There is no command, argument list,
environment or shell in the contract — only a path and scan options.

### Response

The node's canonical `RepositoryResult`, with its provenance re-stamped:

```json
{
  "status": "completed", "state": "COMPLETED",
  "scan_id": "<the node's scan id>",
  "summary": {"total_vulnerabilities": 30, "dismissed_unreachable": 26,
              "actionable": 4, "suspicious_packages": 1,
              "noise_reduced_percent": 86.7},
  "vulnerabilities": ["... the node's evidence, byte-for-byte ..."],
  "artifacts": null,
  "execution": {
    "mode": "remote", "node": "<label or host:port>",
    "remote_scan_id": "<the node's scan id>", "latency_ms": 4120,
    "artifacts_remote": true,
    "note": "the scan ran on <node>; its artifacts (report.json, ...) were
             written on that machine and this deployment stores none of them"
  }
}
```

Three deliberate properties:

1. **`artifacts` is `null`.** The node's artifact paths name files on *its* disk;
   forwarding them would invite a caller to open a path that does not exist here.
   The note states which artifact files exist remotely, so nothing is implied.
2. **The node's own `execution` block is replaced.** The node ran the engine
   locally and correctly says `mode: "local"`; from this deployment's point of
   view — and for its caller — the truthful answer is `mode: "remote"`.
3. **Evidence is never rewritten.** The reply is validated against the canonical
   model and then forwarded as it arrived, so unknown evidence fields survive the
   hop exactly as they survive a local scan. A reply with an unknown top-level
   key, a missing field or a non-JSON body is refused as
   `REMOTE_INVALID_RESPONSE` rather than normalised.

## 4. Artifact contract

The four canonical artifacts are `report.json`, `trace.json`, `sbom.cdx.json`
and `openvex.json`. They are produced by the engine on whichever machine runs
it, and the read-only artifact route
(`/scans/{scan_id}/repositories/{repository_id}/artifacts/{name}`) serves them
from **that** machine's workspace. The coordinator neither mirrors nor rewrites
them; `artifact_names` tells a caller what to fetch and `execution.note` says
where from.

## 5. Error states

Every remote failure has exactly one HTTP answer and one code, defined once in
[`remote.py`](remote.py) (`FAILURE_MAP`) and covered by tests.

| Code | HTTP | Meaning |
|---|---|---|
| `REMOTE_EXECUTION_DISABLED` | 503 | the gate is closed (the default state) |
| `REMOTE_EXECUTION_NOT_CONFIGURED` | 503 | gate open, no usable node URL |
| `REMOTE_CLIENT_UNAVAILABLE` | 503 | the HTTP client is not installed (local scans unaffected) |
| `REMOTE_ENGINE_UNAVAILABLE` | 503 | the node's own engine is not runnable |
| `REMOTE_UNREACHABLE` | 502 | the node could not be reached |
| `REMOTE_AUTH_REJECTED` | 502 | the node rejected our token |
| `REMOTE_INVALID_RESPONSE` | 502 | the reply does not match the canonical contract |
| `REMOTE_HTTP_ERROR` | 502 | any other unexpected answer, including a redirect |
| `REMOTE_REQUEST_REJECTED` | 400 | the node refused the request (path or body) |
| `REMOTE_PATH_NOT_ALLOWED` | 400 | remote path relative, NUL-bearing, or outside the declared root |
| `REMOTE_TIMEOUT` | 504 | the node did not answer in time (`state: TIMEOUT`, `status: timeout`) |

These are distinguishable from security findings and from local engine
failures: a remote failure still carries `execution.mode: "remote"`, so a caller
is never told a scan happened here when it did not. A failed remote scan is
never presented as a clean result, and a partial one is never presented as
complete.

## 6. Timeout and failure semantics

- **Bounded per scan:** `CHAIN_GUARD_REMOTE_TIMEOUT_SECONDS` (default 300) governs
  the coordinator→node call and maps to `REMOTE_TIMEOUT` / HTTP 504.
- **Bounded concurrency:** remote scans reuse the existing worker pool
  (`MAX_CONCURRENT_SCANS`), so a fleet cannot exceed the deployment's limit.
- **Failure isolation:** one failing repository in a fleet is reported per
  repository (`partial`), and never cancels its siblings.
- **No fallback:** a named remote failure is never retried locally.
- **No retry loop:** a remote fleet is N calls through the bounded pool; retrying
  is the caller's decision.

## 7. Authentication placeholder

`CHAIN_GUARD_REMOTE_TOKEN` / `CHAIN_GUARD_REMOTE_TOKEN_FILE` supply an optional
bearer token, sent as `Authorization: Bearer …`. It is read from the environment
or a file — never from a command-line argument, where it would be visible in the
shell history and the process table — is excluded from `repr`, never logged,
never echoed in a response, and the preflight re-scans its own report for the
value before returning it.

**No authentication is implemented beyond this header, and no credentials exist
in this workspace.** Nothing in this repository contains a real token; the token
is a placeholder for the future bridge.

## 8. Security restrictions

The client contract cannot express, and the node contract must not accept:

- arbitrary command or shell execution;
- arbitrary filesystem paths (paths are contained on both sides);
- arbitrary URL fetching — the base URL comes from configuration, not a request;
- arbitrary Python execution;
- repository cloning;
- unrestricted artifact retrieval (the artifact allowlist is fixed);
- redirects (a 3xx is refused rather than followed, so a token cannot be
  redirected to another host).

Additional client-side rules: TLS or loopback only (plain `http` to a
non-loopback host is reported as a warning), bounded timeouts, response
validation before forwarding, and no secrets in output.

## 9. Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CHAIN_GUARD_EXECUTION_MODE` | `local` | default mode for a scan that does not choose one |
| `CHAIN_GUARD_REMOTE_ENABLED` | `false` | the gate; empty is *not* true |
| `CHAIN_GUARD_REMOTE_URL` | *(unset)* | node base URL |
| `CHAIN_GUARD_REMOTE_TOKEN` | *(unset)* | bearer token |
| `CHAIN_GUARD_REMOTE_TOKEN_FILE` | *(unset)* | token file (one trailing newline ignored) |
| `CHAIN_GUARD_REMOTE_TIMEOUT_SECONDS` | `300` | per-scan round-trip budget |
| `CHAIN_GUARD_REMOTE_HEALTH_TIMEOUT_SECONDS` | `10` | preflight probe budget |
| `CHAIN_GUARD_REMOTE_ALLOWED_ROOT` | *(unset)* | required prefix for remote paths, as the node sees them |
| `CHAIN_GUARD_REMOTE_LABEL` | host:port | display name for the node |

Naming follows the existing `CHAIN_GUARD_*` convention used by
`CHAIN_GUARD_ALLOWED_ROOT` / `CHAIN_GUARD_ENGINE_ROOT` and by the canonical
integration contract, rather than the `CHAINGUARD_*` spelling in the original
preparation brief.

## 10. Compatibility and versioning

- API version `1.0.0`; the coordinator speaks the canonical `RepositoryResult` /
  `FleetResponse` models unchanged, so a node needs no bespoke endpoint.
- Additive fields do not break compatibility: `execution` is an additive
  extension of the contract in `INTEGRATION_CONTRACT.md`, and
  `execution.mode` accepts `local | remote | fleet` so the canonical value set
  validates. Per-result provenance is emitted as `local` or `remote`, which is
  strictly more precise than a fleet-wide value.
- The engine CLI contract is untouched (`--out-dir`, `--no-llm`,
  `--fail-on-actionable`, `--diff`, `--dashboard`).

## 11. Intentionally not implemented yet

- **No live transport is enabled.** The gate is closed by default; a deployment
  must opt in explicitly, and the preparation phase requires that it stay closed.
- **No artifact transfer.** Artifacts remain on the machine that produced them.
- **No dashboard changes.** The UI sends no `execution_mode`, so it scans
  locally; showing or choosing a node from the UI is a later step.
- **No authentication implementation** beyond the optional bearer header, and no
  secret material in the tree.
- **No queue, retry or scheduling.** No background service, no LAN tunnelling, no
  port exposure by this work.
- **No friend-laptop assumptions.** The node is expected to be an unmodified
  ChainGuard API; compatibility workarounds for an unverified implementation are
  explicitly out of scope, and the preflight exists to measure a node rather than
  trust it.
- **No second scanner, engine, API or result format.**

## 12. Verifying a node (when the gate is opened)

```bash
python -m chainguard_api.remote_check --enable --url http://<node-host>:8010
python -m chainguard_api.remote_check --enable --url http://<node-host>:8010 \
    --token-file ./node.token --allowed-root <node-allowed-root> \
    --probe-repository <dir-on-the-node>
```

Read-only by default (it reads `/health` and `/openapi.json` and probes how
`/scan` answers methods and invalid bodies); a real scan runs only with
`--probe-repository`. Checks: `enabled`, `configured`, `token`, `reachable`,
`health_contract`, `engine`, `contract`, `scan_method_guard`,
`scan_requires_body`, `scan_rejects_unknown_fields`, `auth_enforced`,
`scan_probe`, `secret_hygiene`. `--json` prints the report; `--strict` treats
warnings as failures; exit codes are `0` pass (or warnings), `1` failure, `2`
usage error. The same report is available over HTTP as `GET /remote`, without the
probe scan.

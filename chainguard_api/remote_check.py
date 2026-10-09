"""Preflight a ChainGuard node from the command line (read-only by default).

Run this against the other machine *before* trusting it as an execution node:

    python -m chainguard_api.remote_check --url http://127.0.0.1:8010

It reads the node's ``/health`` and ``/openapi.json``, checks how ``/scan``
answers methods and bodies it should refuse (without ever submitting a valid
scan request), and reports one line per check plus a verdict.

Nothing on the node is modified by the default pass. A real scan runs only when
``--probe-repository`` names a directory the node is allowed to read, which is
the strongest proof that the bridge actually works end to end.

This tool makes an outbound request, so it obeys the same gate as the service:
remote execution is disabled unless ``--enable`` is passed or
``CHAIN_GUARD_REMOTE_ENABLED`` is truthy. Without the gate it reports that fact
and probes nothing at all.

The token is read from an environment variable or a file -- never from an
argument, which would be visible in the process table and the shell history --
and is never printed.

Exit codes: ``0`` pass (or warnings), ``1`` failure (or any warning with
``--strict``), ``2`` usage error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import RemoteNodeConfig, read_token_file
from .remote import verify_remote_node

GLYPHS = {"pass": "  ok  ", "warn": " warn ", "fail": " FAIL ", "skipped": " skip "}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m chainguard_api.remote_check",
        description="Verify a ChainGuard execution node against the canonical contract.",
    )
    parser.add_argument("--url", default=os.environ.get("CHAIN_GUARD_REMOTE_URL", ""),
                        help="node base URL (default: $CHAIN_GUARD_REMOTE_URL)")
    parser.add_argument("--enable", action="store_true",
                        help="allow the probe to make a network call (the gate is "
                             "closed otherwise; also settable through "
                             "CHAIN_GUARD_REMOTE_ENABLED)")
    parser.add_argument("--label", default=os.environ.get("CHAIN_GUARD_REMOTE_LABEL", ""),
                        help="display name for the node in the report")
    parser.add_argument("--token-env", default="CHAIN_GUARD_REMOTE_TOKEN",
                        help="environment variable holding the bearer token "
                             "(default: CHAIN_GUARD_REMOTE_TOKEN)")
    parser.add_argument("--token-file", default="",
                        help="file holding the bearer token (one trailing newline "
                             "is ignored); the environment variable wins if both are set")
    parser.add_argument("--allowed-root", default=os.environ.get("CHAIN_GUARD_REMOTE_ALLOWED_ROOT", ""),
                        help="declared allowed root for repository paths, as the node sees it")
    parser.add_argument("--timeout", type=float, default=None,
                        help="per-scan round-trip budget in seconds (default: 300)")
    parser.add_argument("--health-timeout", type=float, default=None,
                        help="preflight probe budget in seconds (default: 10)")
    parser.add_argument("--probe-repository", default="",
                        help="run one real scan on the node against this directory "
                             "(the only step that changes anything on the node)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--strict", action="store_true",
                        help="treat warnings as failures (exit 1)")
    return parser


def _env_enabled() -> bool:
    """The gate, read the same way the service reads it."""
    raw = (os.environ.get("CHAIN_GUARD_REMOTE_ENABLED") or "").strip().lower()
    return bool(raw) and raw not in {"0", "false", "no", "off"}


def _config_from_args(args: argparse.Namespace) -> RemoteNodeConfig:
    token = os.environ.get(args.token_env) or None
    token_error = None
    if token is None and args.token_file:
        token, token_error = read_token_file(args.token_file)
    defaults = RemoteNodeConfig()
    return RemoteNodeConfig(
        enabled=bool(args.enable) or _env_enabled(),
        url=(args.url or "").strip() or None,
        token=token,
        label=(args.label or "").strip() or None,
        allowed_root=(args.allowed_root or "").strip() or None,
        timeout_seconds=args.timeout or defaults.timeout_seconds,
        health_timeout_seconds=args.health_timeout or defaults.health_timeout_seconds,
        token_error=token_error,
    )


def _print_human(report: dict) -> None:
    node = report.get("remote") or {}
    print(f"node     : {node.get('url') or '<not configured>'}")
    if node.get("allowed_root"):
        print(f"root     : {node['allowed_root']} (declared remote allowed root)")
    auth = node.get("auth")
    print("auth     : " + ("bearer token (value never printed)" if auth == "token"
                           else "none"))
    print()
    for check in report.get("checks", []):
        timing = f" [{check['latency_ms']} ms]" if "latency_ms" in check else ""
        print(f"{GLYPHS.get(check['status'], check['status']):>7} "
              f"{check['name']:<28} {check['detail']}{timing}")
    print()
    verdict = report.get("verdict", "fail")
    if verdict == "pass":
        print("VERDICT: pass -- the node matches the canonical contract.")
    elif verdict == "warn":
        print("VERDICT: usable with warnings -- read the 'warn' lines above.")
    else:
        print("VERDICT: fail -- fix the 'FAIL' lines on the node before bridging to it.")
    if not (report.get("remote") or {}).get("enabled", False):
        print("Remote execution is disabled on this deployment; nothing was probed. "
              "Re-run with --enable (or set CHAIN_GUARD_REMOTE_ENABLED=true) to "
              "verify a node.")
        return
    if report.get("scan_probe") is None:
        print("Tip: re-run with --probe-repository <dir-on-the-node> to prove a real "
              "scan works end to end.")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    config = _config_from_args(args)
    # A missing URL is only an operator error once the gate is open; with the
    # gate closed the report itself explains the state (and exits non-zero).
    if config.enabled and not (args.url or "").strip():
        print("error: remote execution is enabled but no node URL was given; pass "
              "--url or set CHAIN_GUARD_REMOTE_URL", file=sys.stderr)
        return 2
    report = verify_remote_node(config, probe_repository=args.probe_repository or None)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_human(report)

    verdict = report.get("verdict")
    if verdict == "fail":
        return 1
    if verdict == "warn" and args.strict:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

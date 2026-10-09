"""FastAPI application for horizontal (fleet) repository scanning.

``create_app`` is a factory so tests can inject their own Settings and a
controlled runner; ``app`` is the production instance used by uvicorn.
"""
from __future__ import annotations

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .artifacts import create_artifacts_router
from .auth import install_access_control, is_authorized
from .config import Settings, get_settings
from .engine import engine_executable, health_payload, verify_engine
from .remote import RemoteOutcome, scan_remote, verify_remote_node
from .schemas import FleetRequest, FleetResponse, HealthResponse, RepositoryResult, ScanRequest
from .service import Runner, aggregate_fleet, scan_repository

ERROR_400 = {"INVALID_REPOSITORY", "INVALID_REPOSITORY_ID", "INVALID_OUTPUT_DIRECTORY"}

#: Provenance stamped on results produced by the engine on this machine.
LOCAL_EXECUTION: dict[str, Any] = {"mode": "local", "artifacts_remote": False}


def _options_payload(options: Any) -> dict[str, Any]:
    return {
        "no_llm": options.no_llm,
        "fail_on_actionable": options.fail_on_actionable,
        "dashboard": options.dashboard,
        "diff_ref": options.diff_ref,
    }


def _timeout_result(repo_id: str, repo_path: str) -> dict[str, Any]:
    return {
        "repository": {"id": repo_id, "path": repo_path},
        "status": "timeout",
        "state": "TIMEOUT",
        "scan": None,
        "summary": None,
        "vulnerabilities": [],
        "suspicious_packages": [],
        "artifacts": None,
        "artifact_names": {"report": "report.json", "sbom": "sbom.cdx.json",
                           "vex": "openvex.json", "trace": "trace.json"},
        "execution": dict(LOCAL_EXECUTION),
        "error": {"code": "SCAN_TIMEOUT",
                  "message": "scan exceeded the configured timeout"},
    }


def _redacted_health(payload: dict[str, Any]) -> dict[str, Any]:
    """What an unauthenticated caller may learn: liveness and engine readiness only.

    The engine path, entrypoint, missing modules, detail text and the remote node
    stay with authenticated callers.
    """
    engine = payload.get("engine") or {}
    return {
        "status": payload.get("status", "degraded"),
        "engine": {"available": bool(engine.get("available")),
                   "implementation": engine.get("implementation", "missing")},
        "auth": {"required": True},
    }


def create_app(settings: Settings | None = None, runner: Runner | None = None,
               remote_transport: Any = None) -> FastAPI:
    settings = settings or get_settings()
    pool = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans,
                              thread_name_prefix="chainguard-scan")

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        pool.shutdown(wait=False, cancel_futures=True)

    # With a token configured the interactive API docs are not served: they
    # would publish every route and schema to anonymous visitors.
    hide_docs = bool(settings.api_token)
    app = FastAPI(
        title="ChainGuard API",
        version="1.0.0",
        description=("Horizontal scanning layer around the REAL ChainGuard engine, "
                     "which can optionally execute on a configured remote node."),
        lifespan=lifespan,
        docs_url=None if hide_docs else "/docs",
        redoc_url=None if hide_docs else "/redoc",
        openapi_url=None if hide_docs else "/openapi.json",
    )
    app.state.settings = settings
    app.state.runner = runner
    app.state.pool = pool
    #: Injectable transport for the remote node (tests only; production uses the
    #: real network through httpx).
    app.state.remote_transport = remote_transport

    # Token gate on scan/artifact/remote routes, and the request-size cap.
    install_access_control(app, settings)

    # Read-only artifact serving (additive; the four scanner artifacts only).
    app.include_router(create_artifacts_router(settings))

    # Static dashboard. Optional: when the directory is absent the API behaves
    # exactly as before (no /ui routes), which keeps injected-Settings tests and
    # headless deployments unaffected.
    frontend = Path(settings.frontend_dir) if settings.frontend_dir else None
    if frontend is not None and frontend.is_dir():
        app.mount("/ui", StaticFiles(directory=str(frontend), html=True),
                  name="dashboard")

        @app.get("/", include_in_schema=False)
        async def dashboard_redirect() -> Any:
            return RedirectResponse(url="/ui/")

    async def _in_pool(fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(pool, lambda: fn(*args, **kwargs))

    def _engine_gate() -> str | None:
        """None when the real engine is usable, otherwise the reason it is not."""
        status = verify_engine(settings.engine_root)
        if not status.available:
            return status.detail or "real ChainGuard engine not found"
        ok, detail = engine_executable(settings.engine_root,
                                       settings.python_executable)
        return None if ok else detail

    def _scan_one(repo_id: str, repo_path: str, out_dir: Path,
                  options: dict[str, Any]) -> dict[str, Any]:
        return scan_repository(repo_path, out_dir, options, settings=settings,
                               runner=runner, repository_id=repo_id)

    def _scan_remote(repo_id: str, repo_path: str,
                   options: dict[str, Any]) -> RemoteOutcome:
        """Run one scan on the configured node (never on this machine)."""
        return scan_remote(repo_id, repo_path, options, settings.remote,
                           transport=remote_transport)

    def _execution_mode(options: Any) -> str:
        """The caller's choice when given, otherwise this deployment's default.

        An unrecognised value falls back to ``local``, so a typo can never make
        the service claim a scan ran somewhere it did not.
        """
        chosen = getattr(options, "execution_mode", None)
        if chosen in ("local", "remote"):
            return chosen
        return settings.execution_mode if settings.execution_mode in ("local", "remote") else "local"

    @app.get("/health", response_model=HealthResponse)
    async def health(request: Request) -> Any:
        payload = await _in_pool(health_payload, settings.engine_root,
                                 settings.python_executable)
        if not is_authorized(request.headers, settings):
            # Returned directly: the response model would fill every default
            # field back in and the redacted shape would not be the shape sent.
            return JSONResponse(content=_redacted_health(payload))
        # Disclosure, not a probe: a health check must not depend on whether the
        # node is reachable. GET /remote answers that question.
        payload["remote"] = settings.remote.redacted()
        payload["auth"] = {"required": bool(settings.api_token)}
        if settings.execution_mode == "remote" and not settings.remote.configured:
            payload["status"] = "degraded"
        return payload

    @app.get("/remote", tags=["remote"],
             summary="Preflight the configured node without running a scan")
    async def remote_preflight() -> Any:
        """Verify the node against the canonical contract (read-only).

        Probing never submits a valid scan request, so this endpoint cannot
        start work on the node; the opt-in probe scan lives in the CLI
        (``python -m chainguard_api.remote_check --probe-repository ...``).
        """
        return await _in_pool(verify_remote_node, settings.remote, transport=remote_transport)

    @app.post("/scan", response_model=RepositoryResult,
              responses={400: {"model": RepositoryResult},
                         502: {"model": RepositoryResult},
                         503: {"model": RepositoryResult},
                         504: {"model": RepositoryResult}})
    async def scan(request: ScanRequest) -> Any:
        if _execution_mode(request.options) == "remote":
            # The local engine is irrelevant when the scan runs on the node, so
            # the local readiness gate must not block it. Every remote failure
            # arrives already normalised with its own HTTP answer.
            outcome: RemoteOutcome = await _in_pool(
                _scan_remote, request.repository.id, request.repository.path,
                _options_payload(request.options))
            if outcome.http_status != 200:
                return JSONResponse(status_code=outcome.http_status, content=outcome.result)
            return outcome.result

        reason = await _in_pool(_engine_gate)
        if reason:
            body = {
                "repository": {"id": request.repository.id, "path": request.repository.path},
                "status": "failed", "state": "ENGINE_ERROR", "scan": None, "summary": None,
                "vulnerabilities": [], "suspicious_packages": [], "artifacts": None,
                "artifact_names": {"report": "report.json", "sbom": "sbom.cdx.json",
                                   "vex": "openvex.json", "trace": "trace.json"},
                "execution": dict(LOCAL_EXECUTION),
                "error": {"code": "ENGINE_UNAVAILABLE", "message": reason},
            }
            return JSONResponse(status_code=503, content=body)

        scan_id = uuid.uuid4().hex
        out_dir = settings.workspace_dir / scan_id / request.repository.id
        result = await _in_pool(
            _scan_one, request.repository.id, request.repository.path, out_dir,
            _options_payload(request.options))
        # Artifact identity: lets a client build /scans/<id>/repositories/<repo>/
        # artifacts/<name> links from a single-repository response too.
        result["scan_id"] = scan_id
        # Provenance is set on every answer, success or failure.
        result["execution"] = dict(LOCAL_EXECUTION)

        error = result.get("error") or {}
        if error.get("code") in ERROR_400:
            return JSONResponse(status_code=400, content=result)
        if error.get("code") == "ENGINE_UNAVAILABLE":
            return JSONResponse(status_code=503, content=result)
        if result.get("status") == "timeout":
            return JSONResponse(status_code=504, content=result)
        return result

    @app.post("/scan/fleet", response_model=FleetResponse,
              responses={503: {"model": FleetResponse}})
    async def fleet(request: FleetRequest) -> Any:
        remote = _execution_mode(request.options) == "remote"
        # Only the local path needs a local engine.
        reason = None if remote else await _in_pool(_engine_gate)
        if reason:
            body = {
                "scan_id": "none",
                "status": "failed",
                "summary": {"total_repositories": len(request.repositories),
                            "completed": 0, "failed": len(request.repositories),
                            "total_vulnerabilities": 0, "dismissed_unreachable": 0,
                            "actionable": 0, "suspicious_packages": 0,
                            "noise_reduced_percent": 0.0},
                "results": [],
                "error": {"code": "ENGINE_UNAVAILABLE", "message": reason},
            }
            return JSONResponse(status_code=503, content=body)

        scan_id = uuid.uuid4().hex
        options = _options_payload(request.options)
        if remote:
            async def run(repo: Any) -> dict[str, Any]:
                outcome: RemoteOutcome = await _in_pool(_scan_remote, repo.id, repo.path,
                                                       options)
                return outcome.result
        else:
            async def run(repo: Any) -> dict[str, Any]:
                return await _in_pool(_scan_one, repo.id, repo.path,
                                      settings.workspace_dir / scan_id / repo.id, options)

        jobs = [run(repo) for repo in request.repositories]
        # Bounded by the pool (MAX_CONCURRENT_SCANS); a failure in one task
        # cannot cancel the others because each job is its own executor call.
        settled = await asyncio.gather(*jobs, return_exceptions=True)

        results: list[dict[str, Any]] = []
        for repo, item in zip(request.repositories, settled):
            if isinstance(item, BaseException):
                results.append(_failed_exception(repo.id, repo.path, item))
            else:
                results.append(item)
            # A remote result keeps the id the node assigned and its own
            # provenance: its artifacts live on that machine, so stamping this
            # run's local scan id on it would point at files that do not exist.
            if (results[-1].get("execution") or {}).get("mode") != "remote":
                results[-1]["execution"] = dict(LOCAL_EXECUTION)
                results[-1]["scan_id"] = scan_id

        summary = aggregate_fleet(results)
        completed = summary["completed"]
        status = ("completed" if completed == len(results) and results
                  else "failed" if completed == 0 else "partial")
        return {"scan_id": scan_id, "status": status, "summary": summary, "results": results}

    return app


def _failed_exception(repo_id: str, repo_path: str, exc: BaseException) -> dict[str, Any]:
    return {
        "repository": {"id": repo_id, "path": repo_path},
        "status": "failed",
        "state": "ENGINE_ERROR",
        "scan": None,
        "summary": None,
        "vulnerabilities": [],
        "suspicious_packages": [],
        "artifacts": None,
        "artifact_names": {"report": "report.json", "sbom": "sbom.cdx.json",
                           "vex": "openvex.json", "trace": "trace.json"},
        "execution": dict(LOCAL_EXECUTION),
        "error": {"code": "SCAN_FAILED", "message": f"{type(exc).__name__}: {exc}"},
    }


app = create_app()

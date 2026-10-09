"""Stable API schemas around the real scanner output.

Field names may be normalised here, but no real evidence is dropped: every
model allows extra fields so scanner keys that are not modelled explicitly
still round-trip into API responses.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

REPOSITORY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"

ExecutionMode = Literal["local", "remote"]


class RepositoryRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=REPOSITORY_ID_PATTERN,
                    description="Directory-safe identifier for this repository")
    path: str = Field(min_length=1, description="Absolute path inside the allowed root")


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    no_llm: bool = True
    fail_on_actionable: bool = False
    dashboard: bool = False
    diff_ref: str | None = None
    #: Where the engine runs. ``None`` means "use this deployment's default"
    #: (``CHAIN_GUARD_EXECUTION_MODE``, which itself defaults to ``local``).
    #: ``remote`` is refused with 503 when no remote node is configured -- the service
    #: never silently falls back to a local scan, because the caller asked for
    #: a specific machine and a different one would be a false answer.
    execution_mode: ExecutionMode | None = Field(
        default=None,
        description="local (this deployment) or remote (the configured remote node)")


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: RepositoryRef
    options: ScanOptions = ScanOptions()


class Vulnerability(BaseModel):
    """Every field required by the contract, plus anything else the engine emits."""

    model_config = ConfigDict(extra="allow")

    id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: list[Any] = Field(default_factory=list)
    fixed_version: str | None = None
    package: dict[str, Any] = Field(default_factory=dict)
    status: str = ""
    justification: str | None = None
    impact_statement: str | None = None
    evidence: dict[str, Any] | None = None


class SuspiciousPackage(BaseModel):
    model_config = ConfigDict(extra="allow")

    package: dict[str, Any] = Field(default_factory=dict)
    suspicious: bool = False
    status: str = ""
    reasons: list[str] = Field(default_factory=list)


class Summary(BaseModel):
    model_config = ConfigDict(extra="allow")

    total_vulnerabilities: int = 0
    dismissed_unreachable: int = 0
    actionable: int = 0
    suspicious_packages: int = 0
    noise_reduced_percent: float = 0.0


class ScanMeta(BaseModel):
    exit_code: int
    duration_ms: int
    command: list[str] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""


class Artifacts(BaseModel):
    """Absolute locations of the raw scanner artifacts, plus API-level names."""

    report: str | None = None
    sbom: str | None = None
    vex: str | None = None
    trace: str | None = None
    dashboard: str | None = None
    stdout_log: str | None = None
    stderr_log: str | None = None


class ArtifactNames(BaseModel):
    """API-level mapping: logical name -> real on-disk file name."""

    report: str = "report.json"
    sbom: str = "sbom.cdx.json"
    vex: str = "openvex.json"
    trace: str = "trace.json"


class ErrorInfo(BaseModel):
    code: str
    message: str


class ExecutionInfo(BaseModel):
    """Provenance of one repository result.

    The service runs the engine on this machine or on a configured remote node;
    a caller must be able to tell which, without guessing from the payload.
    Nothing here is a secret: the token is never echoed.
    """

    model_config = ConfigDict(extra="forbid")

    mode: ExecutionMode
    #: Remote node label (host:port). ``None`` for a local scan.
    node: str | None = None
    #: The id the remote node assigned to its scan, when the run was remote.
    remote_scan_id: str | None = None
    #: Round-trip wall time of the remote call, measured locally.
    latency_ms: int | None = None
    #: True when the canonical artifacts exist on the node, not on this
    #: deployment -- so ``artifacts`` is deliberately empty.
    artifacts_remote: bool = False
    note: str | None = None


ScanState = Literal["COMPLETED", "ACTIONABLE", "INVALID_INPUT", "ENGINE_ERROR", "TIMEOUT"]
ScanStatus = Literal["completed", "failed", "timeout"]


class RepositoryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: RepositoryRef
    #: The scan id this repository's artifacts are stored under
    #: (`/scans/<scan_id>/repositories/<id>/artifacts/<name>`). Additive field.
    scan_id: str | None = None
    status: ScanStatus
    state: ScanState
    scan: ScanMeta | None = None
    summary: Summary | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    suspicious_packages: list[SuspiciousPackage] = Field(default_factory=list)
    #: Manifest declarations the engine could not resolve to one exact version
    #: (unpinned/ranged/wildcard/placeholder/unparseable). The engine discloses
    #: them so a scan can never look clean because part of the inventory was
    #: silently dropped; the API must not discard that disclosure.
    unresolved_dependencies: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: Artifacts | None = None
    artifact_names: ArtifactNames = ArtifactNames()
    #: Which machine produced this result and where its artifacts were written.
    #: A remote result has no local artifacts at all; saying so is the point.
    execution: ExecutionInfo | None = None
    #: Placeholder for future ML advisory risk score (always null until ML module implemented).
    risk_assessment: dict[str, Any] | None = None
    error: ErrorInfo | None = None


class ScanResponse(RepositoryResult):
    pass


class FleetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repositories: list[RepositoryRef] = Field(min_length=1, max_length=50)
    options: ScanOptions = ScanOptions()


class FleetSummary(BaseModel):
    total_repositories: int = 0
    completed: int = 0
    failed: int = 0
    total_vulnerabilities: int = 0
    dismissed_unreachable: int = 0
    actionable: int = 0
    suspicious_packages: int = 0
    noise_reduced_percent: float = 0.0


class FleetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: Literal["completed", "partial", "failed"]
    summary: FleetSummary
    results: list[RepositoryResult]


class EngineInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    available: bool
    version: str | None = None
    implementation: Literal["real", "missing"]
    type: str = "real"
    path: str | None = None
    entrypoint: str = "chainguard_mvp.cli"
    executable: bool | None = None
    detail: str | None = None
    missing: list[str] | None = None


class RemoteInfo(BaseModel):
    """Disclosure of the configured remote node. Never includes the token.

    ``/health`` reports this as information: it deliberately does *not* probe
    the node (a health check must not depend on the network), so a caller that
    wants a verdict runs the preflight at ``GET /remote``.
    """

    model_config = ConfigDict(extra="forbid")

    #: The gate. ``False`` means remote execution is disabled on this
    #: deployment, in which case ``configured`` is ``False`` too and no entry
    #: point may open a connection to a node.
    enabled: bool = False
    configured: bool
    url: str | None = None
    node: str | None = None
    auth: Literal["token", "none"] = "none"
    allowed_root: str | None = None
    token_error: str | None = None


class AuthInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: True when scan, artifact and remote routes need ``Authorization: Bearer``.
    required: bool


class HealthResponse(BaseModel):
    """Unauthenticated callers get a redacted form (no engine path, no remote)."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded"]
    engine: EngineInfo
    #: Informational only; it never changes ``status`` (see :class:`RemoteInfo`).
    remote: RemoteInfo | None = None
    auth: AuthInfo | None = None

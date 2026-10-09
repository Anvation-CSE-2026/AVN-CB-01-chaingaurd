/* Client for the existing ChainGuard API. This module never decides anything
 * security-related: it posts scan requests and reads artifacts back verbatim.
 *
 * The dashboard is served from the same origin under /ui, so the default base
 * is "" (relative). A different base can be injected with
 * window.CHAINGUARD_API_BASE (for example when serving the UI from a dev
 * server) — it is a plain string, never derived from a request.
 */

const BASE = (typeof window !== "undefined" && window.CHAINGUARD_API_BASE) || "";

/* Access token for a deployment that requires one. It is held in this module's
 * memory only: never in storage, never in a URL, never logged. Reloading the
 * page clears it, and the operator types it again in Settings. */
let accessToken = null;

export function setAccessToken(value) {
  const cleaned = String(value || "").trim();
  accessToken = cleaned || null;
}

export function hasAccessToken() {
  return Boolean(accessToken);
}

function authHeaders(extra = {}) {
  return accessToken ? { ...extra, Authorization: `Bearer ${accessToken}` } : { ...extra };
}

export class ApiError extends Error {
  constructor(message, { status = 0, code = "UNKNOWN", detail = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

function extractError(status, payload) {
  const detail = payload && typeof payload === "object" ? payload.detail : null;
  if (detail && typeof detail === "object" && detail.code) {
    return { code: detail.code, message: detail.message || detail.code };
  }
  const inner = payload && typeof payload === "object" ? payload.error : null;
  if (inner && typeof inner === "object" && inner.code) {
    return { code: inner.code, message: inner.message || inner.code };
  }
  if (typeof detail === "string") return { code: `HTTP_${status}`, message: detail };
  return { code: `HTTP_${status}`, message: `the API responded with status ${status}` };
}

async function request(path, { method = "GET", body = null, signal = null } = {}) {
  let response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers: authHeaders(body ? { "Content-Type": "application/json" } : {}),
      body: body ? JSON.stringify(body) : undefined,
      signal: signal || undefined,
      cache: "no-store",
      credentials: "same-origin",
    });
  } catch (error) {
    if (error && error.name === "AbortError") throw error;
    throw new ApiError("cannot reach the ChainGuard API", { code: "API_UNAVAILABLE", detail: error });
  }
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = { detail: text.slice(0, 400) }; }
  }
  if (!response.ok) {
    const { code, message } = extractError(response.status, payload);
    throw new ApiError(message, { status: response.status, code, detail: payload });
  }
  return payload;
}

export function getHealth() {
  return request("/health");
}

/** POST /scan — one repository, real engine, real artifacts. */
export function postScan({ id, path, options }, { signal } = {}) {
  return request("/scan", {
    method: "POST",
    body: { repository: { id, path }, options },
    signal,
  });
}

/** POST /scan/fleet — bounded-concurrency multi-repository scan. */
export function postFleet({ repositories, options }, { signal } = {}) {
  return request("/scan/fleet", {
    method: "POST",
    body: { repositories, options },
    signal,
  });
}

export const ARTIFACTS = ["report.json", "trace.json", "sbom.cdx.json", "openvex.json"];

export function artifactUrl(scanId, repositoryId, name, { download = false } = {}) {
  const base = `${BASE}/scans/${encodeURIComponent(scanId)}/repositories/`
    + `${encodeURIComponent(repositoryId)}/artifacts/${encodeURIComponent(name)}`;
  return download ? `${base}?download=true` : base;
}

/** Fetch one scanner artifact as JSON. Returns null when it does not exist. */
export async function fetchArtifact(scanId, repositoryId, name, { signal } = {}) {
  try {
    const response = await fetch(artifactUrl(scanId, repositoryId, name),
      { cache: "no-store", signal, headers: authHeaders() });
    if (response.status === 404) return { missing: true, data: null, error: null };
    if (!response.ok) {
      const text = await response.text();
      let payload = null;
      try { payload = JSON.parse(text); } catch { payload = null; }
      const { code, message } = extractError(response.status, payload);
      return { missing: false, data: null, error: new ApiError(message, { status: response.status, code }) };
    }
    const data = await response.json();
    return { missing: false, data, error: null };
  } catch (error) {
    if (error && error.name === "AbortError") throw error;
    return { missing: false, data: null,
             error: new ApiError("cannot reach the ChainGuard API", { code: "API_UNAVAILABLE", detail: error }) };
  }
}

/** View or download one artifact. A plain link cannot carry the bearer token,
 *  so the bytes are fetched with it and handed to the browser as a blob URL. */
export async function openArtifact(scanId, repositoryId, name, { download = false } = {}) {
  const response = await fetch(artifactUrl(scanId, repositoryId, name),
    { cache: "no-store", headers: authHeaders() });
  if (!response.ok) {
    const text = await response.text();
    let payload = null;
    try { payload = JSON.parse(text); } catch { payload = null; }
    const { code, message } = extractError(response.status, payload);
    throw new ApiError(message, { status: response.status, code });
  }
  const url = URL.createObjectURL(await response.blob());
  if (download) {
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
  } else {
    window.open(url, "_blank", "noopener");
  }
  window.setTimeout(() => URL.revokeObjectURL(url), 60000);
}

/** Load report/trace/sbom/openvex for one scan (parallel, partial-safe). */
export async function loadArtifacts(scanId, repositoryId, { signal } = {}) {
  const names = { report: "report.json", trace: "trace.json", sbom: "sbom.cdx.json", vex: "openvex.json" };
  const entries = await Promise.all(Object.entries(names).map(async ([key, name]) => {
    const outcome = await fetchArtifact(scanId, repositoryId, name, { signal });
    return [key, name, outcome];
  }));
  const data = {};
  const loaded = {};
  const errors = {};
  for (const [key, name, outcome] of entries) {
    if (outcome.data) { data[key] = outcome.data; loaded[key] = true; continue; }
    loaded[key] = false;
    errors[key] = outcome.missing
      ? { code: "ARTIFACT_MISSING", message: `${name} was not produced for this repository` }
      : { code: outcome.error?.code || "ARTIFACT_ERROR", message: outcome.error?.message || `${name} could not be read` };
  }
  return { data, loaded, errors };
}

/** Client-side option validation mirrors the API contract, so no request is sent
 *  for input the API would reject anyway. The API remains the authority. */
export function validateRepositoryPath(path) {
  const value = String(path || "").trim();
  if (!value) return { ok: false, code: "INVALID_REPOSITORY", message: "a repository path is required" };
  if (value.includes("\u0000")) return { ok: false, code: "INVALID_REPOSITORY", message: "the path contains a NUL byte" };
  return { ok: true };
}

export function validateRepositoryId(id) {
  const value = String(id || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value)) {
    return { ok: false, code: "INVALID_REPOSITORY_ID",
             message: "the scan label must be 1-64 characters of letters, digits, dot, dash or underscore" };
  }
  return { ok: true };
}

/** Human-readable description of a failure, used by every error state. */
export function describeError(error, context = {}) {
  const code = error?.code || "UNKNOWN";
  const map = {
    UNAUTHORIZED: {
      title: "Access token required",
      tone: "warn",
      body: "This ChainGuard deployment requires an access token. Nothing was scanned.",
      hint: "Open Settings and enter the token. It stays in this tab's memory and must be entered again after a reload.",
    },
    REQUEST_TOO_LARGE: {
      title: "Request too large",
      tone: "error",
      body: error?.message || "The request body exceeded the API's size limit.",
      hint: null,
    },
    API_UNAVAILABLE: {
      title: "API unavailable",
      tone: "error",
      body: "The dashboard could not reach the ChainGuard API. Nothing was scanned and no result "
        + "is being shown — this is not a safe state.",
      hint: "Start the service with: uvicorn chainguard_api.app:app --host 127.0.0.1 --port 8010",
    },
    ENGINE_UNAVAILABLE: {
      title: "Security engine unavailable",
      tone: "error",
      body: "The API is running but the real ChainGuard engine is not usable, so no scan can produce "
        + "a trustworthy verdict.",
      hint: "Check GET /health for the engine path, entrypoint and missing modules.",
    },
    INVALID_REPOSITORY: {
      title: "Invalid repository path",
      tone: "error",
      body: error?.message || "The path was rejected by the API's path validation.",
      hint: "Paths must resolve inside CHAIN_GUARD_ALLOWED_ROOT and exist on this machine.",
    },
    INVALID_REPOSITORY_ID: {
      title: "Invalid scan label",
      tone: "error",
      body: error?.message || "The repository id was rejected.",
      hint: "It becomes a directory name, so only letters, digits, dot, dash and underscore are accepted.",
    },
    INVALID_OUTPUT_DIRECTORY: {
      title: "Invalid output directory",
      tone: "error",
      body: error?.message || "The scan output directory escaped the allowed root.",
      hint: "Scan outputs must stay inside the configured workspace.",
    },
    SCAN_TIMEOUT: {
      title: "Scan timed out",
      tone: "error",
      body: error?.message || "The engine exceeded the configured timeout and was terminated.",
      hint: "Raise SCAN_TIMEOUT_SECONDS or reduce the repository size, then run the scan again.",
    },
    SCAN_INVALID_INPUT: {
      title: "Engine rejected the target",
      tone: "error",
      body: error?.message || "The scanner exited with code 2 (invalid input).",
      hint: "Confirm the path contains a supported manifest and, for --diff, that the git ref exists.",
    },
    OUTPUT_MISSING: {
      title: "No supported manifest",
      tone: "error",
      body: error?.message || "The engine finished but produced no report.json.",
      hint: "The repository may contain no manifest this scanner supports.",
    },
    SCAN_FAILED: {
      title: "Scan failed",
      tone: "error",
      body: error?.message || "The engine exited with an unexpected code.",
      hint: "The captured stdout/stderr are recorded next to the artifacts.",
    },
    ENGINE_EXECUTION_FAILED: {
      title: "Scan failed",
      tone: "error",
      body: error?.message || "The engine process could not be executed.",
      hint: "Check CHAIN_GUARD_PYTHON and that the engine's dependencies are installed.",
    },
    ARTIFACT_MISSING: {
      title: "Artifact not available",
      tone: "warn",
      body: error?.message || "This artifact was not produced for the selected repository.",
      hint: "Only files that exist on disk are exposed; nothing is synthesised.",
    },
    ARTIFACT_ERROR: {
      title: "Artifact could not be read",
      tone: "error",
      body: error?.message || "The artifact endpoint returned an error.",
      hint: null,
    },
  };
  const known = map[code] || {
    title: code === "UNKNOWN" ? "Unknown result" : code.replace(/_/g, " "),
    tone: "error",
    body: error?.message || "The request failed and no security conclusion can be drawn from it.",
    hint: null,
  };
  return { code, ...known, status: error?.status || 0, context };
}

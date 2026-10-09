/* ChainGuard dashboard shell.
 *
 * Responsibilities: build the chrome (sidebar, top bar, drawer, palette,
 * toasts), route between views, own the scan/analysis state, and expose the
 * context object each view renders from. No security decision is made here:
 * results come from the API and its artifacts, and are passed through.
 */

import { el, mount, clear, icon, shorten } from "./dom.js";
import {
  button, errorState, reachabilityPath, searchInput, stateBlock, trustSignalRow,
} from "./components.js";
import * as api from "./api.js";
import {
  buildAnalysis, filterFindings, historyEntry, postureOf, searchAll, sortFindings,
} from "./model.js";
import {
  DEFAULT_VIEW, PLANNED_NAV, PRIMARY_NAV, VIEWS, hashFor, isFindingRoute, parseHash,
} from "./router.js";
import { fmtDateTime, num, timeAgo } from "./format.js";
import { renderFinding } from "./views/vulnerabilities.js";

const HISTORY_KEY = "chainguard.history.v1";
const HISTORY_LIMIT = 25;
const HEALTH_INTERVAL_MS = 30000;

const state = {
  health: null,
  healthError: null,
  analysis: null,
  fleet: null,
  history: [],
  scan: { running: false, label: null, startedAt: null, elapsedSeconds: 0, error: null,
          lastRequest: null, controller: null },
  view: DEFAULT_VIEW,
  param: null,
  ui: {},
  drawerOrigin: null,
  hashBeforeDrawer: null,
};

const ui = {
  view: null, nav: null, topbar: null, topbarTarget: null, topbarStats: null,
  sidebarStatus: null, drawerHost: null, drawerPanel: null, drawerBody: null,
  palette: null, paletteInput: null, paletteResults: null, paletteItems: [], paletteIndex: 0,
  toasts: null, liveRegion: null,
};

let elapsedTimer = null;
let healthTimer = null;
let lastHealthWord = null;

/* ---- small state helpers ------------------------------------------------- */

function uiFor(view) {
  if (!state.ui[view]) {
    state.ui[view] = { query: "", sort: null, page: 1, filters: {} };
  }
  return state.ui[view];
}

function setUi(patch) {
  Object.assign(uiFor(state.view), patch);
  render();
}

function resetUi() {
  state.ui[state.view] = { query: "", sort: null, page: 1, filters: {} };
  render();
}

function loadHistory() {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.slice(0, HISTORY_LIMIT) : [];
  } catch {
    return [];
  }
}

function persistHistory() {
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history.slice(0, HISTORY_LIMIT)));
  } catch {
    /* storage may be unavailable (private mode): history then lives in memory only */
  }
}

function pushHistory(entry) {
  if (!entry.scanId) return;
  state.history = [entry, ...state.history.filter((item) => !(item.scanId === entry.scanId
    && item.repositoryId === entry.repositoryId))].slice(0, HISTORY_LIMIT);
  persistHistory();
}

/* ---- chrome -------------------------------------------------------------- */

function buildSidebar() {
  const nav = el("nav", { class: "nav", "aria-label": "Primary" });
  nav.appendChild(el("span", { class: "nav-label", text: "Workspace" }));
  for (const view of PRIMARY_NAV) {
    const spec = VIEWS[view];
    nav.appendChild(el("button", {
      class: "nav-item", type: "button", dataset: { view },
      onclick: () => navigate(view),
    }, el("span", { class: "nav-glyph" }, icon(spec.glyph, 14)), spec.label));
  }
  nav.appendChild(el("span", { class: "nav-label", style: { marginTop: "var(--sp-3)" },
                               text: "Planned" }));
  for (const view of PLANNED_NAV) {
    const spec = VIEWS[view];
    nav.appendChild(el("button", {
      class: "nav-item", type: "button", dataset: { view }, title: spec.blurb,
      onclick: () => navigate(view),
    }, el("span", { class: "nav-glyph" }, icon(spec.glyph, 14)), spec.label,
      el("span", { class: "nav-tag", text: "SOON" })));
  }

  const status = el("div", { class: "sidebar-foot" }, el("span", { class: "nav-label", text: "System" }));
  ui.sidebarStatus = status;
  return el("aside", { class: "sidebar", id: "sidebar" },
    el("div", { class: "brand" },
      el("span", { class: "brand-mark", "aria-hidden": "true", text: "CG" }),
      el("span", { class: "brand-text" },
        el("span", { class: "brand-name", text: "ChainGuard" }),
        el("span", { class: "brand-sub", text: "supply-chain security" }))),
    nav,
    status);
}

function updateSidebarStatus() {
  const node = ui.sidebarStatus;
  if (!node) return;
  const engine = state.health?.engine || null;
  const rows = [];
  const apiWord = state.health ? state.health.status : (state.healthError ? "unreachable" : "checking");
  rows.push(trustSignalRow("API", apiWord,
    apiWord === "ok" ? "ok" : apiWord === "degraded" ? "warn" : "bad",
    state.healthError?.message || null));
  rows.push(trustSignalRow("Engine", engine?.implementation || "unknown",
    engine?.available ? "ok" : "bad",
    engine?.path ? shorten(engine.path, 30) : "engine path unknown"));
  rows.push(trustSignalRow("Engine version",
    state.analysis?.runMetadata?.tool_version || null, "idle", null));
  rows.push(trustSignalRow("Last scan",
    state.analysis?.runMetadata?.timestamp
      ? timeAgo(state.analysis.runMetadata.timestamp)
      : (state.analysis ? "reopened from artifacts" : null),
    "idle", null));
  rows.push(trustSignalRow("Scan status",
    state.analysis ? postureOf(state.analysis).word.toLowerCase() : null, "idle", null));
  mount(node, el("span", { class: "nav-label", text: "System" }), ...rows,
    el("button", { class: "nav-item", type: "button", onclick: () => navigate("settings") },
      el("span", { class: "nav-glyph" }, icon("lock", 14)), "Settings"));
}

function buildTopbar() {
  ui.topbarTarget = el("div", { class: "topbar-target", text: "no scan loaded" });
  ui.topbarStats = el("div", { class: "topbar-stats" });
  return el("header", { class: "topbar" },
    el("button", { class: "btn menu-toggle", type: "button", "aria-label": "Toggle navigation",
                   onclick: () => document.body.classList.toggle("nav-open") }, icon("menu", 14)),
    el("div", { class: "topbar-context" },
      el("span", { class: "topbar-eyebrow", text: "Repository" }),
      ui.topbarTarget),
    ui.topbarStats,
    el("div", { class: "topbar-actions" },
      button([icon("search", 13), " Search…"], { onClick: () => openPalette() }),
      button([icon("refresh", 13), " Health"], { onClick: () => refreshHealth(true) })));
}

function updateTopbar() {
  const analysis = state.analysis;
  ui.topbarTarget.textContent = analysis
    ? `${analysis.label} — ${shorten(analysis.target || "unknown target", 60)}`
    : "no scan loaded";
  ui.topbarTarget.title = analysis?.target || "";
  const posture = postureOf(analysis);
  const stats = [
    ["Status", state.scan.running ? "scanning" : posture.word.toLowerCase()],
    ["Last scan", analysis?.runMetadata?.timestamp ? timeAgo(analysis.runMetadata.timestamp) : "never"],
    ["Scan id", analysis?.scanId ? shorten(analysis.scanId, 12) : "—"],
  ];
  mount(ui.topbarStats, ...stats.map(([key, value]) => el("div", { class: "topbar-stat" },
    el("span", { class: "k", text: key }),
    el("span", { class: "v", text: String(value) }))));
  const current = document.title;
  void current;
}

/* ---- drawer -------------------------------------------------------------- */

function buildDrawer() {
  ui.drawerBody = el("div", { class: "drawer-body" });
  ui.drawerPanel = el("div", { class: "drawer-panel", role: "dialog", "aria-modal": "true",
                               "aria-label": "Finding investigation" },
    el("header", { class: "drawer-head" },
      el("div", {},
        el("div", { class: "drawer-title", text: "Investigation" }),
        el("div", { class: "drawer-sub", text: "deterministic verdict, evidence and reachability path" })),
      button("Close", { onClick: () => closeFinding(), variant: "quiet" })),
    ui.drawerBody);
  ui.drawerHost = el("div", { class: "drawer-host", hidden: true },
    el("button", { class: "drawer-backdrop", type: "button", "aria-label": "Close investigation",
                   onclick: () => closeFinding() }),
    ui.drawerPanel);
  return ui.drawerHost;
}

function renderDrawer(ctx) {
  if (!isFindingRoute(ctx.route)) {
    ui.drawerHost.hidden = true;
    return;
  }
  ui.drawerHost.hidden = false;
  const finding = state.analysis?.findings.find((item) => item.key === ctx.route.param) || null;
  mount(ui.drawerBody, finding
    ? renderFinding(ctx, finding)
    : stateBlock({ tone: "idle", mark: "?", title: "Finding not available",
        body: "This link points at a finding that is not in the currently loaded scan. "
          + "Loaded scan data is the only source for this view — nothing is fetched or guessed.",
        actions: [button("Back to findings", { onClick: () => closeFinding(), variant: "primary" })] }));
  ui.drawerPanel.querySelector(".drawer-sub").textContent = finding
    ? `${finding.packageName}@${finding.packageVersion} · ${finding.id}` : "no matching finding";
}

/* ---- command palette ----------------------------------------------------- */

function buildPalette() {
  ui.paletteInput = el("input", { class: "palette-input", type: "search", role: "combobox",
                                  "aria-expanded": "true", "aria-controls": "palette-results",
                                  "aria-label": "Search loaded scan data",
                                  placeholder: "Search packages, advisories, files, scan ids…",
                                  autocomplete: "off", spellcheck: "false" });
  ui.paletteResults = el("div", { class: "palette-results", id: "palette-results", role: "listbox" });
  ui.paletteInput.addEventListener("input", () => {
    ui.paletteIndex = 0;
    renderPaletteResults(ui.paletteInput.value);
  });
  ui.paletteInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const delta = event.key === "ArrowDown" ? 1 : -1;
      if (ui.paletteItems.length) {
        ui.paletteIndex = (ui.paletteIndex + delta + ui.paletteItems.length) % ui.paletteItems.length;
        ui.paletteItems[ui.paletteIndex].focus();
      }
    }
  });
  ui.palette = el("div", { class: "palette", hidden: true, role: "dialog", "aria-modal": "true",
                           "aria-label": "Global search" },
    el("div", { class: "palette-panel" },
      ui.paletteInput,
      ui.paletteResults,
      el("p", { class: "palette-hint",
                text: "Searches the currently loaded scan only — the API exposes no search endpoint. "
                  + "Esc closes, Enter opens." })));
  return ui.palette;
}

function renderPaletteResults(query) {
  const results = searchAll(state.analysis, query);
  ui.paletteItems = [];
  ui.paletteIndex = 0;
  if (!state.analysis) {
    mount(ui.paletteResults, el("p", { class: "palette-empty",
      text: "No scan loaded yet. Run a scan and its findings, packages and evidence locations become searchable." }));
    return;
  }
  if (query.trim().length < 2) {
    mount(ui.paletteResults, el("p", { class: "palette-empty",
      text: `Type at least two characters. Searching ${num(state.analysis.findings.length)} findings, `
        + `${num(state.analysis.packages.length)} packages and every recorded evidence location.` }));
    return;
  }
  if (!results.length) {
    mount(ui.paletteResults, el("p", { class: "palette-empty",
      text: `No match for “${query}” in the loaded scan.` }));
    return;
  }
  const items = results.map((result) => {
    const node = el("button", { class: "palette-item", type: "button", role: "option",
                                "aria-selected": "false" },
      el("span", { style: { display: "flex", flexDirection: "column" } },
        el("span", { text: result.label }),
        el("span", { class: "field-hint", text: result.sub })),
      el("span", { class: "kind", text: result.kind }));
    node.addEventListener("click", () => openSearchResult(result));
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); openSearchResult(result); }
    });
    node.addEventListener("focus", () => {
      for (const other of ui.paletteItems) other.setAttribute("aria-selected", "false");
      node.setAttribute("aria-selected", "true");
    });
    return node;
  });
  ui.paletteItems = items;
  mount(ui.paletteResults, ...items);
  items[0].focus();
}

function openSearchResult(result) {
  closePalette();
  if (result.kind === "Finding" || result.kind === "Call site" || result.kind === "Import") {
    openFinding(result.to.param);
  } else {
    navigate(result.to.view, result.to.param || null);
  }
}

function openPalette() {
  ui.palette.hidden = false;
  ui.paletteInput.value = "";
  renderPaletteResults("");
  ui.paletteInput.focus();
}

function closePalette() {
  ui.palette.hidden = true;
}

/* ---- toasts -------------------------------------------------------------- */

function toast(tone, title, body = null) {
  const node = el("div", { class: `toast toast--${tone === "error" ? "error"
    : tone === "ok" ? "ok" : "info"}`, role: tone === "error" ? "alert" : "status" },
    el("span", { class: "toast-title", text: title }),
    body ? el("span", { text: body }) : null);
  ui.toasts.appendChild(node);
  const ttl = tone === "error" ? 10000 : 6000;
  window.setTimeout(() => node.remove(), ttl);
}

/* ---- navigation ---------------------------------------------------------- */

function navigate(view, param = null) {
  const target = hashFor(view, param);
  if (window.location.hash === target) {
    applyRoute(target);
    return;
  }
  window.location.hash = target;
}

function openFinding(key) {
  state.hashBeforeDrawer = window.location.hash || hashFor(state.view);
  state.drawerOrigin = state.view;
  navigate("vulnerabilities", key);
}

function closeFinding() {
  const origin = state.drawerOrigin;
  state.drawerOrigin = null;
  state.hashBeforeDrawer = null;
  if (origin && origin !== "vulnerabilities") navigate(origin);
  else navigate("vulnerabilities");
}

function applyRoute(hash) {
  const route = parseHash(hash);
  state.view = route.view;
  state.param = route.param;
  document.body.classList.remove("nav-open");
  render();
  if (ui.liveRegion) ui.liveRegion.textContent = `${VIEWS[state.view].label} view loaded`;
}

/* ---- scan actions -------------------------------------------------------- */

async function runScan({ repositories, options }) {
  if (!repositories?.length) return;
  const label = repositories[0].id;
  state.scan = {
    running: true, label: repositories.length > 1 ? `${repositories.length} repositories` : label,
    startedAt: Date.now(), elapsedSeconds: 0, error: null,
    lastRequest: { repositories, options }, controller: new AbortController(),
  };
  state.fleet = null;
  startElapsedTimer();
  render();

  try {
    if (repositories.length === 1) {
      const result = await api.postScan({
        id: repositories[0].id, path: repositories[0].path, options,
      }, { signal: state.scan.controller.signal });
      await adoptResult(result, { label, options });
    } else {
      const payload = await api.postFleet({ repositories, options },
        { signal: state.scan.controller.signal });
      state.fleet = payload;
      const first = (payload.results || []).find((item) => item.status === "completed");
      if (first) await adoptResult(first, { label: first.repository.id, options });
      const failed = (payload.summary?.failed || 0);
      toast(failed ? "info" : "ok",
        failed ? `Fleet finished with ${failed} failure(s)` : "Fleet scan complete",
        `${payload.summary?.completed || 0} of ${repositories.length} repositories produced reports.`);
    }
    if (repositories.length === 1) {
      const analysis = state.analysis;
      toast(analysis?.error ? "error" : "ok",
        analysis?.error ? "Scan did not complete" : "Scan complete",
        analysis?.error ? (analysis.error.message || analysis.error.code) : postureOf(analysis).basis);
    }
  } catch (error) {
    if (error && error.name === "AbortError") {
      toast("info", "Scan request cancelled", "The API call was aborted; any engine process it started "
        + "finishes on the server, and its artifacts remain on disk.");
    } else {
      const info = api.describeError(error);
      state.scan.error = { code: error.code || "UNKNOWN", message: error.message, status: error.status };
      toast("error", info.title, info.body);
    }
  } finally {
    state.scan.running = false;
    state.scan.controller = null;
    stopElapsedTimer();
    render();
  }
}

function cancelScan() {
  if (state.scan.controller) state.scan.controller.abort();
}

async function adoptResult(result, { label, options }) {
  const scanId = result?.scan_id || null;
  const repositoryId = result?.repository?.id || null;
  let artifacts = { data: {}, loaded: { report: false, trace: false, sbom: false, vex: false }, errors: {} };
  if (scanId && repositoryId) {
    artifacts = await api.loadArtifacts(scanId, repositoryId);
  } else {
    artifacts.errors = { report: { code: "ARTIFACT_MISSING",
      message: "the scan response carried no scan id, so its artifacts could not be addressed" } };
  }
  const analysis = buildAnalysis({
    result, report: artifacts.data.report, trace: artifacts.data.trace,
    sbom: artifacts.data.sbom, vex: artifacts.data.vex,
    scanId, repositoryId, label, options,
    artifactsLoaded: artifacts.loaded, artifactErrors: artifacts.errors,
  });
  state.analysis = analysis;
  pushHistory(historyEntry(analysis));
  for (const [key, error] of Object.entries(artifacts.errors)) {
    if (error.code !== "ARTIFACT_MISSING") {
      toast("error", `${error.code}`, `The ${key} artifact could not be read: ${error.message}`);
    }
  }
}

/** Reopen a scan by id: the API has no scan index, so a run is rebuilt from its
 *  four artifacts and the UI says so where the exit code would be. */
async function loadScanById({ scanId, repositoryId }) {
  if (!scanId || !repositoryId) {
    toast("error", "Scan id and repository id are both required",
      "Artifacts are addressed as /scans/<scan id>/repositories/<repository id>/artifacts/<name>.");
    return;
  }
  const artifacts = await api.loadArtifacts(scanId, repositoryId);
  const report = artifacts.data.report;
  if (!report && artifacts.errors.report?.code === "UNAUTHORIZED") {
    const info = api.describeError(artifacts.errors.report);
    toast("error", info.title, info.hint || info.body);
    return;
  }
  if (!report) {
    toast("error", "No report.json for that scan",
      artifacts.errors.report?.message || "the artifact endpoint returned no report for this repository.");
    return;
  }
  const synthetic = {
    repository: { id: repositoryId, path: report.target || null },
    scan_id: scanId,
    status: "completed",
    state: report.summary?.actionable ? "ACTIONABLE" : "COMPLETED",
    scan: null,
    summary: report.summary || null,
    vulnerabilities: Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [],
    suspicious_packages: Array.isArray(report.suspicious_packages) ? report.suspicious_packages : [],
    unresolved_dependencies: Array.isArray(report.unresolved_dependencies)
      ? report.unresolved_dependencies : [],
    artifacts: null,
    artifact_names: { report: "report.json", trace: "trace.json", sbom: "sbom.cdx.json",
                      vex: "openvex.json" },
    error: null,
  };
  const analysis = buildAnalysis({
    result: synthetic, report, trace: artifacts.data.trace, sbom: artifacts.data.sbom,
    vex: artifacts.data.vex, scanId, repositoryId, label: repositoryId,
    artifactsLoaded: artifacts.loaded, artifactErrors: artifacts.errors,
  });
  analysis.reconstructed = true;
  state.analysis = analysis;
  pushHistory(historyEntry(analysis));
  toast("ok", "Scan reopened from artifacts",
    "The exit code is unknown for a reopened scan because the API stores no scan index — "
    + "run metadata comes from trace.json.");
  navigate("overview");
}

async function openArtifactFile(name, { download }) {
  const analysis = state.analysis;
  if (!analysis?.scanId || !analysis?.repositoryId) {
    toast("error", "No artifact address", "This scan has no scan id/repository id pair to address artifacts with.");
    return;
  }
  const fileName = analysis.artifactNames?.[name] || name;
  try {
    await api.openArtifact(analysis.scanId, analysis.repositoryId, fileName, { download });
  } catch (error) {
    const info = api.describeError(error);
    toast("error", info.title, info.body);
  }
}

function viewArtifact(name) {
  return openArtifactFile(name, { download: false });
}

function downloadArtifact(name) {
  return openArtifactFile(name, { download: true });
}

function saveAccessToken(value) {
  api.setAccessToken(value);
  toast("ok", "Token held for this tab", "It is kept in memory only and cleared on reload.");
  refreshHealth(false);
  render();
}

function clearAccessToken() {
  api.setAccessToken("");
  toast("info", "Token forgotten", "Requests from this tab are now sent without a token.");
  render();
}

function openPackageFindings(pkg) {
  if (!pkg) return;
  state.ui.vulnerabilities = { ...uiFor("vulnerabilities"), filters: {}, query: pkg.name, page: 1 };
  navigate("vulnerabilities");
}

/* ---- health -------------------------------------------------------------- */

async function refreshHealth(announce = false) {
  try {
    state.health = await api.getHealth();
    state.healthError = null;
  } catch (error) {
    state.health = null;
    state.healthError = { code: error.code || "API_UNAVAILABLE", message: error.message,
                          status: error.status };
  }
  const word = state.health?.status || (state.healthError ? "unreachable" : "unknown");
  updateSidebarStatus();
  if (announce) {
    toast(word === "ok" ? "ok" : "error",
      word === "ok" ? "Engine healthy" : `Engine ${word}`,
      word === "ok" ? null : state.healthError?.message || state.health?.engine?.detail || null);
  }
  if (word !== lastHealthWord) {
    lastHealthWord = word;
    render();
  }
}

/* ---- render -------------------------------------------------------------- */

function searchControl() {
  return searchInput({
    value: uiFor(state.view).query || "",
    placeholder: "Search loaded scan data",
    label: "Search in this view",
    onInput: (value) => setUi({ query: value, page: 1 }),
  });
}

function buildCtx() {
  const view = state.view;
  const analysis = state.analysis;
  return {
    state,
    analysis,
    posture: postureOf(analysis),
    route: { view, param: state.param },
    ui: uiFor(view),
    setUi,
    resetUi,
    searchControl,
    filterFindings,
    sortedFindings: sortFindings,
    pathFor: (finding) => reachabilityPath(finding, analysis),
    actions: {
      navigate, openFinding, closeFinding, openPackageFindings,
      runScan, cancelScan, loadScanById, viewArtifact, downloadArtifact,
      toast, refreshHealth, saveAccessToken, clearAccessToken, clearHistory: () => {
        state.history = [];
        persistHistory();
        render();
        toast("info", "History cleared", "Artifacts on disk are untouched.");
      },
    },
  };
}

function keepFocus() {
  const active = document.activeElement;
  if (!active || !ui.view || !ui.view.contains(active)) return null;
  if (!(active.tagName === "INPUT" || active.tagName === "SELECT" || active.tagName === "TEXTAREA")) return null;
  let start = null;
  try { start = active.selectionStart; } catch { start = null; }
  return { name: active.getAttribute("name"), type: active.getAttribute("type"),
           value: active.value, start };
}

function restoreFocus(snapshot) {
  if (!snapshot || !ui.view) return;
  const selector = snapshot.name ? `[name="${snapshot.name}"]` : null;
  const node = selector ? ui.view.querySelector(selector)
    : ui.view.querySelector("input[type=search], input, select, textarea");
  if (!node) return;
  node.focus();
  if (typeof node.setSelectionRange === "function" && snapshot.start !== null
    && snapshot.type === "search") {
    try { node.setSelectionRange(snapshot.value.length, snapshot.value.length); } catch { /* not a text input */ }
  }
}

function render() {
  const snapshot = keepFocus();
  const ctx = buildCtx();
  const spec = VIEWS[state.view] || VIEWS[DEFAULT_VIEW];

  for (const node of ui.nav.querySelectorAll(".nav-item")) {
    if (node.dataset.view === state.view) node.setAttribute("aria-current", "page");
    else node.removeAttribute("aria-current");
  }
  updateSidebarStatus();
  updateTopbar();
  document.title = state.analysis
    ? `ChainGuard · ${spec.label} · ${state.analysis.label}`
    : `ChainGuard · ${spec.label}`;

  let content;
  try {
    content = spec.render(ctx);
  } catch (error) {
    console.error("view render failed", error);
    content = errorState({ code: "VIEW_ERROR", message: String(error?.message || error) }, {
      onRetry: () => navigate(DEFAULT_VIEW),
      retryLabel: "Back to overview",
    });
  }
  mount(ui.view, content);

  renderDrawer(ctx);
  restoreFocus(snapshot);
}

function startElapsedTimer() {
  stopElapsedTimer();
  elapsedTimer = window.setInterval(() => {
    state.scan.elapsedSeconds = Math.floor((Date.now() - state.scan.startedAt) / 1000);
    const node = ui.view?.querySelector(".elapsed");
    if (node) {
      const minutes = String(Math.floor(state.scan.elapsedSeconds / 60)).padStart(2, "0");
      const seconds = String(state.scan.elapsedSeconds % 60).padStart(2, "0");
      node.textContent = `elapsed ${minutes}:${seconds}`;
    }
  }, 1000);
}

function stopElapsedTimer() {
  if (elapsedTimer) window.clearInterval(elapsedTimer);
  elapsedTimer = null;
}

/* ---- boot ---------------------------------------------------------------- */

function buildChrome() {
  const sidebar = buildSidebar();
  ui.nav = sidebar.querySelector(".nav");
  const shell = el("div", { class: "shell" },
    sidebar,
    el("div", { class: "content" },
      buildTopbar(),
      el("main", { class: "main", id: "main" }),
      el("p", { class: "footer-note",
                text: "ChainGuard dashboard — deterministic verdicts from the real scanner. "
                  + "The browser never decides whether code is affected; it renders what the engine recorded." })));
  ui.view = shell.querySelector("#main");
  ui.liveRegion = el("div", { class: "field-hint", "aria-live": "polite",
                              style: { position: "absolute", width: "1px", height: "1px",
                                       overflow: "hidden", clip: "rect(0 0 0 0)" } });
  ui.toasts = el("div", { class: "toasts", "aria-live": "polite", "aria-label": "Notifications" });

  const root = document.getElementById("app");
  clear(root);
  root.appendChild(shell);
  root.appendChild(buildDrawer());
  root.appendChild(buildPalette());
  root.appendChild(ui.toasts);
  root.appendChild(ui.liveRegion);
}

function bindKeys() {
  document.addEventListener("keydown", (event) => {
    const meta = event.metaKey || event.ctrlKey;
    if (meta && event.key.toLowerCase() === "k") {
      event.preventDefault();
      if (ui.palette.hidden) openPalette(); else closePalette();
      return;
    }
    if (event.key === "Escape") {
      if (!ui.palette.hidden) { closePalette(); return; }
      if (!ui.drawerHost.hidden) { closeFinding(); }
    }
  });
}

function boot() {
  state.history = loadHistory();
  buildChrome();
  bindKeys();
  updateSidebarStatus();
  applyRoute(window.location.hash || hashFor(DEFAULT_VIEW));
  refreshHealth();
  healthTimer = window.setInterval(() => refreshHealth(), HEALTH_INTERVAL_MS);
  window.addEventListener("hashchange", () => applyRoute(window.location.hash));
  window.addEventListener("beforeunload", stopElapsedTimer);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}

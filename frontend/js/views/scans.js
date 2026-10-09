/* Scans — start a real scan, watch it honestly, and reopen past scans.
 *
 * The API runs the engine as a subprocess and answers once: it exposes no
 * stage-level progress. So the progress indicator here is explicitly
 * indeterminate and the stage strip only reports what trace.json recorded
 * after the fact. No percentage is ever invented.
 */

import { el, frag, shorten } from "../dom.js";
import {
  button, dataTable, errorState, loadingBlock, mono, panel, stateBlock, stepsStrip,
  toolbar, toolbarCount,
} from "../components.js";
import { STAGE_LABELS } from "../model.js";
import { durationMs, num, pct, timeAgo } from "../format.js";
import { pageHead } from "./common.js";
import { validateRepositoryId, validateRepositoryPath } from "../api.js";

const OPTION_DEFS = [
  ["no_llm", "Disable LLM hints (--no-llm)", true,
   "Every decision path falls back to the deterministic heuristics."],
  ["fail_on_actionable", "Fail on actionable (--fail-on-actionable)", false,
   "Exit code 1 becomes API state ACTIONABLE (status still completed)."],
  ["dashboard", "Also write dashboard.html (--dashboard)", false,
   "The engine's own single-file HTML dashboard becomes an extra artifact."],
];

function optionRow(key, label, value, note) {
  const id = `opt-${key}`;
  return el("div", { class: "checkbox-row", style: { alignItems: "flex-start", gap: "var(--sp-3)" } },
    el("input", { type: "checkbox", id, checked: value ? true : null, value: key,
                  dataset: { option: key } }),
    el("label", { for: id, style: { display: "flex", flexDirection: "column" } },
      el("span", { text: label }),
      el("span", { class: "field-hint", text: note })));
}

export function render(ctx) {
  const { state, analysis } = ctx;
  const running = Boolean(state.scan?.running);
  const options = ctx.ui.options || {};
  const head = pageHead({
    title: "Scans",
    sub: "Initiate a scan, follow it honestly, and reopen earlier runs",
    actions: ctx.state.health ? [
      button("Refresh engine status", { onClick: () => ctx.actions.refreshHealth(), variant: "quiet" }),
    ] : [],
  });

  // ---- new scan form
  const form = el("form", { class: "panel-body", novalidate: true });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const pathValue = form.querySelector("[name=path]").value.trim();
    const labelValue = form.querySelector("[name=label]").value.trim();
    const extraValue = form.querySelector("[name=fleet]").value;
    const validation = validateRepositoryPath(pathValue);
    if (!validation.ok) {
      ctx.actions.toast("error", "Invalid repository path", validation.message);
      form.querySelector("[name=path]").focus();
      return;
    }
    const derived = labelValue || pathValue.split(/[\\/]/).filter(Boolean).pop() || "repository";
    const idCheck = validateRepositoryId(derived.replace(/[^A-Za-z0-9._-]/g, "-"));
    if (!idCheck.ok) {
      ctx.actions.toast("error", "Invalid scan label", idCheck.message);
      return;
    }
    const options = { no_llm: true, fail_on_actionable: false, dashboard: false, diff_ref: null };
    for (const input of form.querySelectorAll("[data-option]")) {
      options[input.dataset.option] = input.checked;
    }
    const diffRef = form.querySelector("[name=diff_ref]").value.trim();
    options.diff_ref = diffRef || null;
    const repositories = [{ id: derived.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64), path: pathValue }];
    for (const line of String(extraValue).split(/\r?\n/).map((item) => item.trim()).filter(Boolean)) {
      const id = (line.split(/[\\/]/).filter(Boolean).pop() || "repository")
        .replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64) || "repository";
      repositories.push({ id, path: line });
    }
    ctx.actions.runScan({ repositories, options });
  });

  form.appendChild(el("div", { class: "fieldset-row" },
    el("div", { class: "field", style: { flex: "1 1 380px" } },
      el("label", { for: "scan-path", class: "field-hint", text: "Repository or manifest path" }),
      el("input", { id: "scan-path", name: "path", type: "text", required: true,
                    placeholder: "C:\\path\\to\\repository  (or /home/you/repo)",
                    autocomplete: "off", spellcheck: "false", disabled: running || undefined })),
    el("div", { class: "field", style: { flex: "0 1 220px" } },
      el("label", { for: "scan-label", class: "field-hint", text: "Scan label (used as the output directory name)" }),
      el("input", { id: "scan-label", name: "label", type: "text", placeholder: "derived from the path",
                    autocomplete: "off", spellcheck: "false", disabled: running || undefined })),
    el("div", { class: "field", style: { flex: "0 1 220px" } },
      el("label", { for: "scan-diff", class: "field-hint", text: "Diff against git ref (optional)" }),
      el("input", { id: "scan-diff", name: "diff_ref", type: "text", placeholder: "e.g. main or a commit sha",
                    autocomplete: "off", spellcheck: "false", disabled: running || undefined }))));

  form.appendChild(el("div", { class: "fieldset-row", style: { marginTop: "var(--sp-4)" } },
    OPTION_DEFS.map(([key, label, fallback, note]) =>
      optionRow(key, label, options[key] === undefined ? fallback : options[key], note))));

  form.appendChild(el("div", { class: "field", style: { marginTop: "var(--sp-4)" } },
    el("label", { for: "scan-fleet", class: "field-hint",
                  text: "Additional repositories (one path per line — uses POST /scan/fleet)" }),
    el("textarea", { id: "scan-fleet", name: "fleet", rows: "3",
                     placeholder: "one absolute path per line", disabled: running || undefined })));

  form.appendChild(el("div", { class: "field-inline", style: { marginTop: "var(--sp-4)" } },
    el("button", { class: "btn btn-primary", type: "submit", disabled: running || undefined },
      running ? "Scan running…" : "Start scan"),
    running ? button("Cancel", { onClick: () => ctx.actions.cancelScan() }) : null,
    el("span", { class: "field-hint", text: "The API applies its own timeout and concurrency limits." })));

  const scanPanel = el("section", { class: "panel" },
    el("header", { class: "panel-head" },
      el("h2", { class: "panel-title", text: "New scan" }),
      el("span", { class: "panel-note",
                   text: "the browser never scans: it asks the API, which runs the real engine as a subprocess" })),
    form,
    el("footer", { class: "panel-foot" },
      el("span", { text: "Paths are validated server-side against the allowed root; the form only rejects "
        + "empty input so no request is wasted." })));

  // ---- progress / result
  let progressPanel = null;
  if (running) {
    progressPanel = panel({
      title: "Scan in progress",
      body: [
        loadingBlock({
          label: `Scanning ${state.scan.label || "repository"}…`,
          elapsedSeconds: state.scan.elapsedSeconds ?? 0,
          hint: "The API reports no stage-level progress, so this indicator is deliberately indeterminate. "
            + "Stage timings appear when trace.json arrives.",
        }),
        el("div", { style: { marginTop: "var(--sp-4)" } },
          stepsStrip(STAGE_LABELS, { activeIndex: -1 })),
        el("div", { class: "field-inline", style: { marginTop: "var(--sp-4)" } },
          button("Cancel request", { onClick: () => ctx.actions.cancelScan(), variant: "quiet" })),
      ],
    });
  } else if (state.scan?.error) {
    progressPanel = panel({
      title: "Last request",
      body: [errorState(state.scan.error, {
        onRetry: state.scan.lastRequest
          ? () => ctx.actions.runScan(state.scan.lastRequest)
          : null,
        retryLabel: "Run again",
        extra: [button("Open the scan form", { onClick: () => {
          const node = document.getElementById("scan-path");
          if (node) node.focus();
        }, variant: "quiet" })],
      })],
    });
  }

  // ---- fleet results
  let fleetPanel = null;
  if (state.fleet) {
    const results = state.fleet.results || [];
    fleetPanel = panel({
      title: "Fleet run",
      note: `status: ${state.fleet.status}`,
      flush: true,
      body: [
        toolbar(
          el("span", { class: "field-hint",
            text: `scan ${state.fleet.scan_id || state.fleet.scanId || "unknown"} — `
              + `${num(results.length)} repositories, bounded concurrency; a failure in one `
              + "repository cannot cancel the others" }),
          toolbarCount(`${num(state.fleet.summary?.completed || 0)} completed · `
            + `${num(state.fleet.summary?.failed || 0)} failed`)),
        dataTable({
          columns: [
            { key: "id", label: "Repository", render: (row) => mono(row.repository.id) },
            { key: "path", label: "Path", render: (row) => el("span", { class: "chain-detail",
              text: shorten(row.repository.path, 56), title: row.repository.path }) },
            { key: "status", label: "Status", render: (row) => el("span", {
              class: `badge ${row.status === "completed" ? "badge--ok"
                : row.status === "partial" ? "badge--warn" : "badge--high"}`,
              text: String(row.status).toUpperCase() }) },
            { key: "counts", label: "Findings", align: "right",
              render: (row) => row.summary
                ? `${num(row.summary.actionable)} actionable / ${num(row.summary.total_vulnerabilities)} total`
                : el("span", { class: "field-hint", text: row.error?.code || "—" }) },
            { key: "action", label: "", class: "cell-actions",
              render: (row) => row.status === "completed"
                ? button("Open results", { variant: "quiet",
                    onClick: () => ctx.actions.loadScanById({
                      scanId: state.fleet.scan_id || state.fleet.scanId,
                      repositoryId: row.repository.id }) })
                : el("span", { class: "field-hint", text: row.error?.message
                    ? shorten(row.error.message, 48) : "" }) },
          ],
          rows: results,
        }),
      ],
    });
  }

  // ---- history
  const history = state.history || [];
  const historyPanel = panel({
    title: "Scan history",
    note: "kept in this browser only — the API exposes no scan list",
    flush: !history.length,
    body: history.length
      ? dataTable({
          columns: [
            { key: "label", label: "Scan", render: (entry) => el("div", {},
                el("div", { class: "pkg", text: entry.label || "repository" }),
                el("div", { class: "field-hint", text: shorten(entry.target || "unknown target", 52) })) },
            { key: "scan", label: "Scan id", render: (entry) => mono(entry.scanId) },
            { key: "when", label: "Started", render: (entry) => timeAgo(entry.startedAt) },
            { key: "status", label: "Status", render: (entry) => el("span", {
                class: `badge ${entry.status === "completed" ? "badge--ok" : "badge--warn"}`,
                text: String(entry.status || "unknown").toUpperCase() }) },
            { key: "counts", label: "Result", align: "right", render: (entry) => entry.counts
                ? `${num(entry.counts.actionable)} actionable / ${num(entry.counts.total)} total`
                : el("span", { class: "field-hint", text: entry.error || "no summary recorded" }) },
            { key: "action", label: "", class: "cell-actions", render: (entry) => button("Reopen", {
                variant: "quiet",
                onClick: () => ctx.actions.loadScanById({ scanId: entry.scanId,
                                                          repositoryId: entry.repositoryId }) }) },
          ],
          rows: history,
        })
      : el("div", { style: { padding: "var(--sp-4)" } },
          stateBlock({ tone: "idle", mark: "∅", title: "No scans yet",
            body: "Run a scan and it will be listed here for the rest of this browser session." })),
    foot: history.length
      ? [button("Clear history", { onClick: () => ctx.actions.clearHistory(), variant: "quiet" }),
         el("span", { text: "Clearing this list removes only browser bookkeeping; artifacts on disk stay." })]
      : null,
  });

  // ---- reopen by id
  const reopenForm = el("form", { class: "panel-body" });
  reopenForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const scanId = reopenForm.querySelector("[name=scan_id]").value.trim();
    const repositoryId = reopenForm.querySelector("[name=repository_id]").value.trim();
    if (!/^[0-9a-f]{32}$/.test(scanId)) {
      ctx.actions.toast("error", "Invalid scan id", "a scan id is 32 lowercase hexadecimal characters");
      return;
    }
    ctx.actions.loadScanById({ scanId, repositoryId });
  });
  reopenForm.appendChild(el("div", { class: "fieldset-row" },
    el("div", { class: "field", style: { flex: "1 1 320px" } },
      el("label", { for: "reopen-scan", class: "field-hint", text: "Scan id" }),
      el("input", { id: "reopen-scan", name: "scan_id", type: "text", placeholder: "0123abcd…",
                    autocomplete: "off", spellcheck: "false" })),
    el("div", { class: "field", style: { flex: "0 1 220px" } },
      el("label", { for: "reopen-repo", class: "field-hint", text: "Repository id" }),
      el("input", { id: "reopen-repo", name: "repository_id", type: "text", placeholder: "repo-id",
                    autocomplete: "off", spellcheck: "false" })),
    el("div", { class: "field-inline" },
      el("button", { class: "btn", type: "submit" }, "Load artifacts"))));

  return frag(
    head,
    el("div", { class: "split", style: { marginTop: "var(--sp-4)" } },
      el("div", {},
        scanPanel,
        progressPanel,
        fleetPanel,
        analysis ? resultsSummary(ctx) : null),
      el("div", {},
        historyPanel,
        panel({ title: "Reopen an existing scan",
                note: "reads the four artifacts back from the API",
                body: [reopenForm] }))));
}

/** Concise summary first, then deep links into the rest of the product (§15). */
function resultsSummary(ctx) {
  const { analysis, posture } = ctx;
  const counts = posture.counts;
  return panel({
    title: "Latest result",
    note: `${analysis.label} · status ${analysis.status}`,
    body: [
      el("div", { class: "field-inline", style: { alignItems: "baseline", gap: "var(--sp-4)" } },
        el("span", { class: "posture-word", dataset: { tone: posture.tone },
                     style: { fontSize: "var(--fs-2xl)" }, text: posture.word }),
        el("span", { class: "field-hint", text: posture.basis })),
      el("div", { class: "section-title", text: "Jump into the evidence" }),
      el("div", { class: "state-actions" },
        button(`Findings (${num(counts.actionable)} actionable)`,
          { onClick: () => ctx.actions.navigate("vulnerabilities"), variant: "primary" }),
        button("Reachability", { onClick: () => ctx.actions.navigate("reachability") }),
        button("Dependencies", { onClick: () => ctx.actions.navigate("dependencies") }),
        button("Trust", { onClick: () => ctx.actions.navigate("trust") }),
        button("Artifacts", { onClick: () => ctx.actions.navigate("reports") })),
      el("div", { class: "section-title", text: "Recorded pipeline" }),
      analysis.stages.length
        ? stepsStrip(STAGE_LABELS, { completedThrough: analysis.stages.length - 1 })
        : stateBlock({ tone: "idle", mark: "?", title: "No stage trace",
            body: "trace.json was not available for this scan, so no per-stage timing is shown." }),
      el("div", { class: "field-hint", style: { marginTop: "var(--sp-2)" },
        text: `Engine wall time ${durationMs(analysis.scan?.duration_ms ?? 0)} · `
          + `noise reduction ${pct(analysis.summaryCounts.noiseReduced ?? 0)} · `
          + `${num(analysis.packages.length)} packages analysed` }),
    ],
  });
}

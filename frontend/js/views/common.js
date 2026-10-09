/* Helpers every view shares: page headers, the "is there anything to show"
 * gate, pagination binding and sort binding.
 *
 * A view is `export function render(ctx) { ... }` returning one DOM node.
 * ctx = {
 *   state:    { health, analysis, history, scan, view, param },
 *   analysis: normalized analysis or null,
 *   posture:  posture object from model.postureOf(),
 *   route:    { view, param, title },
 *   ui:       this view's persisted UI state (query, sort, page, pageSize, filters…),
 *   setUi(patch), resetUi(),
 *   actions:  { navigate, openFinding, closeFinding, runScan, cancelScan,
 *               loadScanById, viewArtifact, downloadArtifact, toast,
 *               refreshHealth, clearHistory, setScanOptions },
 * }
 */

import { el, frag } from "../dom.js";
import { button, emptyState, errorState, pagination, panel, stateBlock } from "../components.js";
import { num } from "../format.js";

export function pageHead({ title, sub = null, actions = [] }) {
  return el("div", { class: "page-head" },
    el("div", { class: "titles" },
      el("h1", { class: "page-title", text: title }),
      sub ? el("p", { class: "page-sub", text: sub }) : null),
    actions.length ? el("div", { class: "page-actions" }, actions) : null);
}

/**
 * Uniform handling of "there is no usable analysis yet".
 * Returns a node when the view must not render scan-dependent content,
 * or null when the caller may continue.
 */
export function analysisGate(ctx, { actionLabel = "Go to scan page" } = {}) {
  const { analysis, state } = ctx;
  if (state.scan?.running) {
    return stateBlock({
      tone: "idle", mark: "◌", title: "Scan in progress",
      body: "Results appear as soon as the engine finishes; the pipeline below shows the stages "
        + "the engine records in trace.json.",
      actions: [button("View scan progress", { onClick: () => ctx.actions.navigate("scans"),
                                              variant: "primary" })],
    });
  }
  if (!analysis) {
    return emptyState({
      title: "No scan loaded",
      body: "This view reads real ChainGuard scan output. Run a scan, or reopen a previous scan "
        + "by its scan id, and the data appears here.",
      actions: [button(actionLabel, { onClick: () => ctx.actions.navigate("scans"), variant: "primary" })],
    });
  }
  if (analysis.error || analysis.status === "failed" || analysis.status === "timeout") {
    return errorState(analysis.error || { code: "SCAN_FAILED", message: "the scan did not complete" }, {
      onRetry: () => ctx.actions.navigate("scans"),
      retryLabel: "Run another scan",
      extra: [button("View raw scan metadata", { onClick: () => ctx.actions.navigate("reports"),
                                                variant: "quiet" })],
    });
  }
  return null;
}

/** Bounded rendering: every list is paginated so the DOM stays small. */
export function usePaged(rows, ui, setUi, defaultPageSize = 25) {
  const pageSize = ui.pageSize || defaultPageSize;
  const total = rows.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(Math.max(1, ui.page || 1), pages);
  const slice = rows.slice((page - 1) * pageSize, page * pageSize);
  const pager = pagination({
    page, pageSize, total,
    onPage: (next) => setUi({ page: Math.min(Math.max(1, next), pages) }),
  });
  return { rows: slice, pager, total, page, pageSize, pages };
}

/** Sort binding for dataTable(th onSort). */
export function useSort(ui, setUi, fallback = { key: "severity", dir: "asc" }) {
  const sort = ui.sort || fallback;
  return {
    sort,
    onSort: (key, dir) => setUi({ sort: { key, dir }, page: 1 }),
  };
}

export function countLabel(shown, total, noun) {
  return `${num(shown)} of ${num(total)} ${noun}`;
}

export function metricStrip(entries) {
  return el("div", { class: "meter" }, entries.map((entry) => el("div", { class: "meter-cell" },
    el("div", { class: "figure", dataset: { tone: entry.tone || "idle" }, text: entry.value }),
    el("div", { class: "cele", text: entry.label }),
    entry.note ? el("div", { class: "field-hint", text: entry.note }) : null)));
}

export { panel, emptyState, errorState, button, frag };

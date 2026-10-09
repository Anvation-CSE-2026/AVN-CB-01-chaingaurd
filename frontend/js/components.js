/* Shared components. Everything is built with el()/text, so scan data can never
 * be interpreted as markup. Severity is always communicated with a glyph plus
 * a word plus a colour, never colour alone (accessibility requirement).
 */

import { el, frag, shorten, icon } from "./dom.js";
import { describeError } from "./api.js";
import {
  fmtDateTime, num, pct, durationMs, elapsedLabel, severityOf, toneForBand,
  justificationText, gradeOf, reachabilityOf, timeAgo, purlParts, days,
} from "./format.js";
import { evidenceLocations, reachabilityStateOf } from "./model.js";

const SEVERITY_GLYPH = { critical: "◆", high: "▲", medium: "●", low: "▬", unknown: "○" };
const REACH_GLYPH = { "not-imported": "×", "no-calls": "×", "calls-found": "✓", unknown: "?" };

// ---- atoms ---------------------------------------------------------------

export function badge(text, tone = "plain", { glyph = null, title = null, plain = false } = {}) {
  return el("span", {
    class: `badge${plain ? " badge--plain" : ` badge--${tone}`}`,
    title,
  }, glyph ? el("span", { class: "glyph", "aria-hidden": "true", text: glyph }) : null, text);
}

export function severityBadge(severity, { showScore = true } = {}) {
  const band = toneForBand(severity?.band || "unknown");
  const scoreText = severity?.score === null || severity?.score === undefined
    ? "" : ` ${Number(severity.score).toFixed(1)}`;
  const title = `${severity?.label || "UNRATED"}${scoreText}`
    + (severity?.basis ? ` — ${severity.basis}` : "")
    + (severity?.vector ? `\n${severity.vector}` : "");
  return badge(`${severity?.label || "UNRATED"}${showScore ? scoreText : ""}`, band,
    { glyph: SEVERITY_GLYPH[band] || "○", title });
}

export function verdictBadge(finding) {
  if (finding.actionable) {
    return badge("ACTIONABLE", "high", { glyph: "▲", title: "engine verdict: affected" });
  }
  if (finding.status === "not_affected") {
    return badge("NOT AFFECTED", "ok", { glyph: "✓", title: "engine verdict: not affected" });
  }
  return badge("UNKNOWN", "unknown", { glyph: "?", title: "the engine reported no verdict" });
}

export function reachabilityBadge(finding) {
  const state = reachabilityStateOf(finding);
  const tone = state === "calls-found" ? "bad" : state === "unknown" ? "unknown" : "ok";
  const words = {
    "not-imported": "NOT IMPORTED",
    "no-calls": "NO CALLS FOUND",
    "calls-found": "CALLS FOUND",
    // The advisory named no function, so the engine kept the finding actionable
    // rather than dismissing it. "Unknown" here means unknown evidence, not safe.
    unknown: "NO FUNCTION DATA",
  };
  return badge(words[state], tone, { glyph: REACH_GLYPH[state], title: reachabilityOf(finding).note });
}

export function gradeBadge(source) {
  const grade = gradeOf(source);
  return badge(grade.word, grade.tone, { plain: true, title: grade.note });
}

export function dot(tone = "idle") {
  const cls = { ok: "dot--ok", warn: "dot--warn", bad: "dot--bad", info: "dot--info" }[tone] || "";
  return el("span", { class: `dot ${cls}`.trim(), "aria-hidden": "true" });
}

export function mono(text, { muted = false, breakAll = false } = {}) {
  return el("span", {
    class: `mono${muted ? " is-muted" : ""}`,
    style: { fontFamily: "var(--font-data)", wordBreak: breakAll ? "break-all" : undefined },
    text: text === null || text === undefined || text === "" ? "Not available" : String(text),
  });
}

export function notAvailable(label = "Not available") {
  return el("span", { class: "field-hint", text: label });
}

// ---- surfaces ------------------------------------------------------------

export function panel({ title = null, note = null, actions = null, foot = null, flush = false,
                        id = null, body = [] } = {}) {
  const node = el("section", { class: "panel", id });
  if (title || actions) {
    node.appendChild(el("header", { class: "panel-head" },
      el("h2", { class: "panel-title", text: title || "" }),
      note ? el("span", { class: "panel-note", text: note }) : null,
      actions ? el("div", { class: "panel-actions" }, actions) : null));
  }
  node.appendChild(el("div", { class: `panel-body${flush ? " flush" : ""}` }, body));
  if (foot) node.appendChild(el("footer", { class: "panel-foot" }, foot));
  return node;
}

export function sectionTitle(text, note = null) {
  return el("h2", { class: "section-title" }, text, note
    ? el("span", { class: "panel-note", text: note }) : null);
}

export function callout(tone, title, body) {
  return el("div", { class: `callout callout--${tone}` },
    el("span", { class: "callout-title", text: title }),
    body ? el("span", { class: "callout-body", text: body }) : null);
}

export function kvList(pairs) {
  const list = el("dl", { class: "kv" });
  for (const pair of pairs) {
    if (!pair) continue;
    const [key, value, opts] = pair;
    list.appendChild(el("dt", { text: key }));
    const rendered = value === null || value === undefined || value === ""
      ? notAvailable(opts?.missing || "Not available")
      : (opts?.mono ? mono(value, { breakAll: opts.breakAll }) : String(value));
    list.appendChild(el("dd", {}, rendered));
  }
  return list;
}

export function stateBlock({ tone = "idle", mark = null, title, body = null, code = null,
                             actions = [] } = {}) {
  return el("div", { class: `state${tone === "error" ? " state--error" : tone === "ok" ? " state--ok" : ""}` },
    mark ? el("span", { class: "state-mark", "aria-hidden": "true", text: mark }) : null,
    el("h3", { class: "state-title", text: title }),
    body ? el("p", { class: "state-body", text: body }) : null,
    code ? el("span", { class: "state-code", text: code }) : null,
    actions.length ? el("div", { class: "state-actions" }, actions) : null);
}

export function emptyState({ title, body, actions = [], tone = "idle" }) {
  return stateBlock({ tone, mark: "∅", title, body, actions });
}

export function errorState(error, { onRetry = null, retryLabel = "Retry", extra = [] } = {}) {
  const info = describeError(error);
  const actions = [];
  if (onRetry) actions.push(button(retryLabel, { onClick: onRetry, variant: "primary" }));
  actions.push(...extra);
  return stateBlock({
    tone: info.tone === "warn" ? "idle" : "error",
    mark: info.tone === "warn" ? "!" : "✕",
    title: info.title,
    body: info.hint ? `${info.body} ${info.hint}` : info.body,
    code: `code: ${info.code}${info.status ? ` · http ${info.status}` : ""}`,
    actions,
  });
}

export function loadingBlock({ label = "Loading…", elapsedSeconds = null, hint = null } = {}) {
  return el("div", { class: "loading", role: "status", "aria-live": "polite" },
    el("div", { class: "loading-line" },
      el("span", { class: "spinner", "aria-hidden": "true" }),
      el("strong", { text: label }),
      elapsedSeconds === null ? null
        : el("span", { class: "elapsed", text: `elapsed ${elapsedLabel(elapsedSeconds)}` })),
    el("div", { class: "progress-track", "aria-hidden": "true" }, el("span", { class: "bar" })),
    hint ? el("span", { class: "field-hint", text: hint }) : null);
}

// ---- controls ------------------------------------------------------------

export function button(label, { onClick = null, variant = "ghost", type = "button", disabled = false,
                               title = null, to = null } = {}) {
  const cls = variant === "primary" ? "btn btn-primary"
    : variant === "quiet" ? "btn btn-quiet" : "btn";
  const node = el(to ? "a" : "button", {
    class: cls,
    type: to ? undefined : type,
    href: to || undefined,
    disabled: to ? undefined : (disabled || undefined),
    title,
    "aria-disabled": disabled ? "true" : null,
    onclick: onClick || undefined,
  }, label);
  return node;
}

export function searchInput({ value = "", placeholder = "Search", label = "Search",
                              onInput = null } = {}) {
  const input = el("input", {
    type: "search", value, placeholder, "aria-label": label, spellcheck: "false",
    autocomplete: "off",
  });
  if (onInput) {
    let timer = null;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(() => onInput(input.value), 120);
    });
  }
  return el("div", { class: "toolbar-search" }, input);
}

export function selectField({ label, value, options, onChange, id = null }) {
  const select = el("select", { id, "aria-label": label, onchange: (event) => onChange(event.target.value) },
    options.map((option) => el("option", {
      value: option.value, selected: option.value === value ? true : null,
      text: option.label,
    })));
  return el("div", { class: "field" }, el("label", { for: id, class: "field-hint", text: label }), select);
}

export function toolbar(children) {
  return el("div", { class: "toolbar" }, children);
}

export function toolbarCount(text) {
  return el("span", { class: "toolbar-count", text });
}

// ---- tables --------------------------------------------------------------

/**
 * columns: [{key, label, sortable, align, width, render(row), title(row), class}]
 */
export function dataTable({ columns, rows, sort = null, onSort = null, onRowClick = null,
                            rowClass = null, rowAttrs = null, caption = null, empty = null }) {
  const table = el("table", { class: "data-table" });
  if (caption) table.appendChild(el("caption", { text: caption }));
  const headRow = el("tr");
  for (const column of columns) {
    const isSorted = sort && sort.key === column.key;
    const th = el("th", {
      scope: "col",
      style: column.width ? { width: column.width } : null,
      "aria-sort": isSorted ? (sort.dir === "desc" ? "descending" : "ascending") : null,
      attrs: column.align === "right" ? { style: "text-align: right" } : null,
    });
    if (column.sortable && onSort) {
      th.appendChild(el("button", {
        type: "button",
        title: `Sort by ${column.label}`,
        onclick: () => onSort(column.key, isSorted && sort.dir === "asc" ? "desc" : "asc"),
      }, column.label));
    } else {
      th.appendChild(el("span", { text: column.label }));
    }
    headRow.appendChild(th);
  }
  table.appendChild(el("thead", {}, headRow));

  const body = el("tbody");
  if (!rows.length && empty) {
    const cell = el("td", { colspan: String(columns.length) }, empty);
    body.appendChild(el("tr", {}, cell));
  }
  for (const row of rows) {
    const tr = el("tr", {
      class: rowClass ? rowClass(row) : null,
      title: null,
      attrs: rowAttrs ? rowAttrs(row) : null,
    });
    if (onRowClick) {
      tr.classList.add("is-clickable");
      tr.tabIndex = 0;
      tr.addEventListener("click", () => onRowClick(row, tr));
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onRowClick(row, tr);
        }
      });
    }
    for (const column of columns) {
      const td = el("td", { class: column.class || null,
                            attrs: column.align === "right" ? { style: "text-align: right" } : null });
      const content = column.render ? column.render(row) : row[column.key];
      if (content !== null && content !== undefined) {
        if (content.nodeType) td.appendChild(content);
        else td.textContent = String(content);
      }
      if (column.title) td.title = String(column.title(row) ?? "");
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
  table.appendChild(body);
  return el("div", { class: "table-wrap" }, table);
}

export function pagination({ page, pageSize, total, onPage }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, pages);
  const from = total === 0 ? 0 : (current - 1) * pageSize + 1;
  const to = Math.min(total, current * pageSize);
  return el("div", { class: "pagination" },
    el("span", { class: "range", text: `${from}–${to} of ${num(total)}` }),
    el("span", { class: "spacer" }),
    button("Previous", { onClick: () => onPage(current - 1), disabled: current <= 1, variant: "quiet" }),
    el("span", { class: "range", text: `page ${current} / ${pages}` }),
    button("Next", { onClick: () => onPage(current + 1), disabled: current >= pages, variant: "quiet" }));
}

// ---- posture meter -------------------------------------------------------

export function postureMeter(posture, analysis) {
  const cells = [
    { key: "actionable", label: "Actionable", value: posture.counts.actionable,
      tone: posture.counts.actionable ? "bad" : "idle", seg: "seg-bad",
      note: "engine verdict: affected" },
    { key: "suspicious", label: "Suspicious packages", value: posture.counts.suspicious,
      tone: posture.counts.suspicious ? "warn" : "idle", seg: "seg-warn",
      note: "registry checks flagged" },
    { key: "unreachable", label: "Dismissed unreachable", value: posture.counts.unreachable,
      tone: "ok", seg: "seg-ok", note: "not affected, with justification" },
    { key: "total", label: "Total advisories", value: posture.counts.total,
      tone: "info", seg: "seg-info", note: "queried for this inventory" },
  ];
  const total = posture.counts.total || 1;
  const segments = [
    { cls: "seg-bad", value: posture.counts.actionable },
    { cls: "seg-warn", value: posture.counts.suspicious },
    { cls: "seg-ok", value: posture.counts.unreachable },
    { cls: "seg-idle", value: Math.max(0, posture.counts.total - posture.counts.actionable
        - posture.counts.unreachable) },
  ];
  const meter = el("div", { class: "meter", role: "group", "aria-label": "Posture counts" });
  for (const cell of cells) {
    meter.appendChild(el("div", { class: "meter-cell" },
      el("div", { class: "figure", dataset: { tone: cell.tone }, text: num(cell.value) }),
      el("div", { class: "cele", text: cell.label }),
      el("div", { class: "field-hint", text: cell.note })));
  }
  const bar = el("div", { class: "meter-bar", "aria-hidden": "true" });
  for (const segment of segments) {
    if (segment.value <= 0) continue;
    bar.appendChild(el("span", { class: segment.cls,
                                 style: { width: `${(segment.value / total) * 100}%` } }));
  }
  return frag(
    el("div", { class: "posture" },
      el("div", { class: "posture-status" },
        el("span", { class: "posture-label", text: "Security status" }),
        el("div", { class: "posture-word", dataset: { tone: posture.tone }, text: posture.word }),
        el("div", { class: "posture-rule" }),
        el("p", { class: "posture-note", text: posture.basis })),
      el("div", {},
        meter,
        el("div", { style: { marginTop: "var(--sp-3)" } }, bar),
        analysis?.summaryCounts?.noiseReduced === null || analysis?.summaryCounts?.noiseReduced === undefined
          ? null
          : el("p", { class: "field-hint", style: { marginTop: "var(--sp-2)" },
                      text: `Noise reduction reported by the engine: ${pct(analysis.summaryCounts.noiseReduced)} — `
                        + "dismissed advisories are annotated with a justification, not deleted." }))),
    analysis?.inconsistencies?.length
      ? callout("warn", "Report consistency check", analysis.inconsistencies.join(" · "))
      : null);
}

// ---- evidence chain ------------------------------------------------------

/** Build the reachability path for one finding from engine evidence only. */
export function reachabilityPath(finding, analysis) {
  const reach = reachabilityOf(finding);
  const nodes = [];
  nodes.push({ stage: "Application", value: analysis?.target || "scan target",
               detail: "repository scanned by the real engine", state: "confirmed" });

  if (reach.imports.length) {
    for (const item of reach.imports.slice(0, 3)) {
      nodes.push({ stage: "Source file", value: `${item.file}${item.line ? `:${item.line}` : ""}`,
                   detail: `${item.kind || "import"} ${item.name || ""}`.trim(), state: "confirmed" });
    }
    if (reach.imports.length > 3) {
      nodes.push({ stage: "Source file", value: `+${reach.imports.length - 3} more import site(s)`,
                   detail: "see the evidence list below", state: "absent" });
    }
  } else {
    nodes.push({ stage: "Source file", value: "no import or require found",
                 detail: "the dependency does not appear in the scanned source", state: "break" });
  }

  if (reach.calls.length) {
    for (const item of reach.calls.slice(0, 3)) {
      nodes.push({ stage: "Function call", value: `${item.name || "unknown"}() at ${item.file}:${item.line}`,
                   detail: "call site matched an advisory-identified function", state: "confirmed" });
    }
  } else {
    nodes.push({
      stage: "Function call",
      value: reach.functions.length
        ? `no calls to ${reach.functions.slice(0, 4).join(", ")}`
        : "no vulnerable function named by the advisory",
      detail: reach.functions.length
        ? "the advisory's functions were searched for and not called"
        : "the advisory text named no function, so no call could be matched",
      state: reach.imported ? "break" : "absent",
    });
  }

  nodes.push({ stage: "Dependency", value: `${finding.packageName}@${finding.packageVersion}`,
               detail: finding.purl || finding.ecosystem, state: "confirmed" });
  nodes.push({ stage: "Vulnerable function",
               value: reach.functions.length ? reach.functions.slice(0, 6).join(", ") : null,
               detail: reach.decisionSource
                 ? `function source: ${reach.decisionSource}` : "the advisory named no function",
               state: reach.functions.length ? (reach.calls.length ? "confirmed" : "break") : "unknown" });
  nodes.push({ stage: "Vulnerability",
               value: `${finding.id}${finding.aliases.length ? ` (${finding.aliases.join(", ")})` : ""}`,
               detail: `${finding.severity.label}${finding.severity.score !== null
                 ? ` · CVSS ${Number(finding.severity.score).toFixed(1)}` : ""}`,
               state: finding.actionable ? "confirmed" : "absent" });
  return {
    nodes,
    reachable: finding.actionable,
    conclusion: finding.actionable
      ? "Path confirmed: a call to an advisory-identified function was found in the scanned source."
      : (finding.justification === "vulnerable_code_not_present"
        ? "Path broken: the dependency is never imported or required in the scanned source."
        : finding.justification === "vulnerable_code_not_in_execute_path"
          ? "Path broken: the dependency is imported, but no call to an advisory function was found."
          : "The engine did not record a reachability conclusion for this finding."),
    grade: reach.grade,
  };
}

export function chainList(path, { maxNodes = 12 } = {}) {
  const list = el("ol", { class: "chain" });
  let index = 0;
  for (const node of path.nodes.slice(0, maxNodes)) {
    index += 1;
    list.appendChild(el("li", { class: "chain-node", dataset: { state: node.state } },
      el("span", { class: "chain-marker", "aria-hidden": "true",
                   text: node.state === "break" ? "✕" : node.state === "confirmed" ? "✓"
                     : node.state === "absent" ? "·" : "?" }),
      el("div", {},
        el("div", { class: "chain-stage", text: `${index}. ${node.stage}` }),
        node.value
          ? el("div", { class: `chain-value${node.state === "break" ? " is-muted" : ""}`,
                        text: shorten(node.value, 120), title: node.value })
          : notAvailable("Not available"),
        node.detail ? el("div", { class: "chain-detail", text: node.detail }) : null)));
  }
  return frag(
    list,
    el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
              text: path.conclusion }));
}

/**
 * One-line version of the path for dense tables: application → evidence →
 * dependency → vulnerability, with an explicit stop marker where the path
 * breaks. It shows only stages the engine recorded.
 */
export function chainCompact(path) {
  const nodes = path.nodes;
  const app = nodes[0] || null;
  const callSite = nodes.find((node) => node.stage === "Function call" && node.state === "confirmed");
  const stop = nodes.find((node) => node.state === "break");
  const dependency = nodes.find((node) => node.stage === "Dependency");
  const vulnerability = nodes[nodes.length - 1];
  const appLabel = app?.value ? String(app.value).split(/[\\/]/).filter(Boolean).pop() : "application";

  const parts = [{ text: appLabel, title: app?.value || "scan target" }];
  if (path.reachable) {
    if (callSite) parts.push({ text: callSite.value, title: `call site: ${callSite.value}` });
    else parts.push({ text: "no function data", title: "the advisory named no function to test for, "
      + "so the engine kept this finding actionable", muted: true });
  } else if (stop) {
    parts.push({ text: stop.value || stop.stage, title: stop.detail || stop.stage, stop: true });
  }
  if (dependency) parts.push({ text: `${dependency.value}`, title: `dependency: ${dependency.value}` });
  if (vulnerability) parts.push({ text: vulnerability.value || vulnerability.stage, title: vulnerability.stage });

  const wrapper = el("span", { class: "chain-compact" });
  parts.forEach((part, index) => {
    if (index) wrapper.appendChild(el("span", { class: "arrow", "aria-hidden": "true", text: "→" }));
    wrapper.appendChild(el("span", { class: "seg" },
      part.stop ? el("span", { class: "stop", "aria-hidden": "true", text: "✕" }) : null,
      el("span", { class: part.muted ? "is-muted" : null, text: shorten(part.text, 30),
                   title: part.title })));
  });
  return wrapper;
}

// ---- scan pipeline -------------------------------------------------------

export function stepsStrip(stageLabels, { completedThrough = -1, activeIndex = -1, failed = false } = {}) {
  return el("ol", { class: "steps", "aria-label": "Engine pipeline stages" },
    stageLabels.map(([key, label], index) => {
      const state = failed && index === Math.max(activeIndex, 0) ? "failed"
        : index <= completedThrough ? "done"
          : index === activeIndex ? "active" : "pending";
      return el("li", { class: "step", dataset: { state }, title: key },
        el("span", { "aria-hidden": "true", text: state === "done" ? "✓" : state === "active" ? "◌"
          : state === "failed" ? "✕" : "·" }),
        el("span", { text: label }));
    }));
}

export function stageTable(stages) {
  if (!stages.length) return notAvailable("the trace artifact was not loaded");
  return dataTable({
    columns: [
      { key: "stage", label: "Stage", render: (row) => mono(row.stage) },
      { key: "in", label: "In", align: "right", render: (row) => num(row.items_in) },
      { key: "out", label: "Out", align: "right", render: (row) => num(row.items_out) },
      { key: "ms", label: "Duration", align: "right", render: (row) => durationMs(row.duration_ms) },
      { key: "started", label: "Started", render: (row) => fmtDateTime(row.started_at) },
      { key: "summary", label: "Recorded summary", render: (row) => el("span", { class: "chain-detail",
        text: shorten(JSON.stringify(row.summary || {}), 110),
        title: JSON.stringify(row.summary || {}, null, 2) }) },
    ],
    rows: stages,
  });
}

// ---- misc ----------------------------------------------------------------

export function planGrid(items) {
  return el("div", { class: "plan-grid" }, items.map((item) => el("div", { class: "plan-card" },
    el("span", { class: "plan-name", text: item.name }),
    el("span", { class: "plan-body", text: item.body }),
    el("span", { class: "plan-state", text: item.state || "COMING SOON" }))));
}

export function evidenceList(items) {
  if (!items.length) return notAvailable("no evidence lines were recorded");
  return el("ul", { class: "evidence-list" }, items.map((item) => el("li", { class: "evidence-item" },
    el("span", { class: "loc", text: `${item.file}${item.line ? `:${item.line}` : ""}` }),
    el("span", { text: item.name || "" }),
    el("span", { class: "kind", text: item.kind === "call" ? "call" : "import" }))));
}

export function artifactRow({ name, path, exists, generatedAt, onView, onDownload }) {
  return el("div", { class: "artifact-row" },
    el("div", {},
      el("div", { class: "artifact-name", text: name }),
      el("div", { class: "artifact-meta", text: exists
        ? [purlParts(name).type ? null : null, path ? shorten(path, 96) : null,
           generatedAt ? `modified ${fmtDateTime(generatedAt)}` : null].filter(Boolean).join(" · ")
        : "not produced for this scan" })),
    el("div", { class: "artifact-actions" },
      exists ? button("View", { onClick: onView, variant: "quiet" }) : null,
      exists ? button("Download", { onClick: onDownload, variant: "quiet" }) : null));
}

export function trustSignalRow(label, value, tone = "idle", note = null) {
  return el("div", { class: "status-line" },
    dot(tone),
    el("span", {}, el("span", { class: "k", text: label })),
    el("span", { class: `v${tone === "ok" ? " is-ok" : tone === "bad" ? " is-bad" : tone === "warn" ? " is-warn" : ""}`,
                 text: value === null || value === undefined ? "Not available" : String(value) }),
    note ? el("span", { class: "field-hint", text: note }) : null);
}

export function registrySummary(registry) {
  if (!registry) {
    return el("div", {}, el("span", { class: "field-hint",
      text: "No registry inspection was recorded for this package." }));
  }
  const rows = [
    el("div", { class: "status-line" },
      dot(registry.suspicious ? "bad" : registry.exists === false ? "bad"
        : registry.lookupError ? "warn" : "ok"),
      el("span", { class: "k", text: "Registry status" }),
      el("span", { class: `v${registry.suspicious ? " is-bad" : registry.lookupError ? " is-warn" : " is-ok"}`,
                   text: registry.status || "unknown" })),
    el("div", { class: "status-line" },
      el("span", { class: "k", text: "Version published" }),
      el("span", { class: "v", text: registry.created ? fmtDateTime(registry.created) : "Not available" })),
    el("div", { class: "status-line" },
      el("span", { class: "k", text: "Package age" }),
      el("span", { class: "v", text: days(registry.ageDays) })),
    el("div", { class: "status-line" },
      el("span", { class: "k", text: "Releases" }),
      el("span", { class: "v", text: registry.releaseCount === null ? "Not available" : num(registry.releaseCount) })),
    el("div", { class: "status-line" },
      el("span", { class: "k", text: "Last lookup" }),
      el("span", { class: `v${registry.lookupError ? " is-warn" : " is-ok"}`,
                   text: registry.lookupError ? `lookup failed: ${registry.lookupError}` : "registry reachable" })),
  ];
  if (registry.similarNames.length) {
    rows.push(el("div", { class: "status-line" },
      dot("warn"),
      el("span", { class: "k", text: "Similar names" }),
      el("span", { class: "v is-warn",
                   text: registry.similarNames.map((item) => `${item.name} (d=${item.distance ?? "?"})`).join(", ") })));
  }
  if (registry.reasons.length) {
    rows.push(callout("danger", "Suspicious package", registry.reasons.join("; ")));
  }
  return el("div", {}, rows);
}

/** Trust as far as the data actually goes: registry facts + SBOM integrity. */
export function trustBadge(pkg) {
  if (!pkg) return badge("NO DATA", "unknown", { glyph: "?",
    title: "this package is not in the scanned inventory" });
  const registry = pkg.registry;
  const digest = (pkg.sbom?.hashes?.length || 0) > 0
    ? `integrity: ${pkg.sbom.hashes.length} digest(s) recorded in the SBOM (not verified)`
    : "integrity: no digest recorded in the SBOM";
  if (registry?.suspicious) {
    return badge("SUSPICIOUS", "high", { glyph: "▲",
      title: `${(registry.reasons || []).join("; ") || "flagged by registry checks"} · ${digest}` });
  }
  if (registry?.exists === false) {
    return badge("NOT FOUND", "high", { glyph: "▲",
      title: `the registry did not have this package version · ${digest}` });
  }
  if (registry?.lookupError) {
    return badge("UNVERIFIED", "warn", { glyph: "?",
      title: `registry lookup failed: ${registry.lookupError} · ${digest}` });
  }
  if (registry) {
    return badge("REGISTRY OK", "ok", { glyph: "✓",
      title: `package exists in the registry, ${registry.releaseCount ?? "unknown"} releases · ${digest}` });
  }
  return badge("NOT INSPECTED", "unknown", { glyph: "?",
    title: `no registry inspection was recorded for this package · ${digest}` });
}

/**
 * Trust facts for the Trust view and the finding drawer. Every entry is either a
 * value that exists in the scan data or an explicit "Not available" — never an
 * invented score.
 */
export function trustFacts(pkg) {
  const registry = pkg?.registry || null;
  const sbom = pkg?.sbom || null;
  const digest = sbom?.hashes?.[0] || null;
  return [
    ["Registry existence", registry ? (registry.exists === null ? null : (registry.exists ? "present" : "absent")) : null,
      "canonical package registry lookup recorded by the scan"],
    ["Registry status", registry?.status || null, "engine's own status word"],
    ["Lookup error", registry?.lookupError || "none recorded", "registry result",
      registry?.lookupError ? "warn" : "ok"],
    ["Version published", registry?.created ? fmtDateTime(registry.created) : null,
      "publish timestamp returned by the registry"],
    ["Package age", registry?.ageDays === null || registry?.ageDays === undefined ? null : days(registry.ageDays),
      "age of the inspected release"],
    ["Release count", registry?.releaseCount === null || registry?.releaseCount === undefined
      ? null : num(registry.releaseCount), "releases published for this package"],
    ["Integrity digest", digest ? `${digest.alg} ${shorten(digest.content, 24)}` : null,
      digest ? "recorded in the SBOM — recorded is not the same as verified" : "no digest was recorded",
      digest ? "ok" : "warn"],
    ["Licenses", sbom?.licenses?.length ? sbom.licenses.join(", ") : null,
      "declared in the SBOM component"],
    ["Distribution refs", sbom?.references?.length ? `${sbom.references.length} recorded` : null,
      sbom?.references?.[0]?.url ? shorten(sbom.references[0].url, 60) : "no external reference recorded"],
    ["SBOM match", pkg?.sbomMatch ? `matched by ${pkg.sbomMatch}` : null,
      "how the SBOM component was joined to the inventory"],
    ["Graph edges", pkg?.edges?.available ? `${pkg.edges.dependsOn.length} out · ${pkg.edges.dependedOnBy.length} in` : null,
      pkg?.edges?.available ? "edges recorded in the SBOM dependency list"
        : "the SBOM carries no dependency graph for this component"],
    ["Signature / attestation", null, "not produced by this engine version"],
    ["Maintainer signals", null, "not produced by this engine version"],
  ];
}

/**
 * ML risk assessment — prepared, disabled until real ML exists.
 *
 * Returns null unless the scan data itself carries a model result, so today the
 * investigation view simply omits the panel: no probability, no confidence and
 * no feature attribution is ever invented, and the deterministic verdict is
 * never displaced by a score. The expected contract is documented in
 * UI_UX_ARCHITECTURE.md §10.
 */
export function riskAssessmentPanel(finding) {
  const assessment = finding?.raw?.risk_assessment || finding?.risk_assessment || null;
  if (!assessment || typeof assessment !== "object") return null;
  const probability = typeof assessment.risk_probability === "number" ? assessment.risk_probability : null;
  const confidence = typeof assessment.confidence === "number" ? assessment.confidence : null;
  const features = Array.isArray(assessment.top_features) ? assessment.top_features : [];
  return panel({
    title: "ML risk assessment",
    note: "advisory only — the deterministic verdict above remains primary",
    body: [
      kvList([
        ["Model version", assessment.model_version || null, { mono: true }],
        ["Risk probability", probability === null ? null : `${(probability * 100).toFixed(1)}%`],
        ["Risk class", assessment.risk_class || null],
        ["Confidence", confidence === null ? null : `${(confidence * 100).toFixed(1)}%`],
      ]),
      features.length
        ? el("div", { class: "section-title", text: "Top contributing features" })
        : null,
      features.length
        ? el("ul", { class: "evidence-list" }, features.map((feature) => el("li", { class: "evidence-item" },
            el("span", { class: "loc", text: String(feature.name || feature.feature || "feature") }),
            el("span", { text: feature.value === undefined ? "" : String(feature.value) }),
            el("span", { class: "kind",
                         text: feature.weight === undefined ? "" : `weight ${feature.weight}` }))))
        : null,
      assessment.explanation
        ? el("p", { class: "chain-detail", text: String(assessment.explanation) })
        : null,
    ].filter(Boolean),
  });
}

export { timeAgo, severityOf, evidenceLocations, icon, days };

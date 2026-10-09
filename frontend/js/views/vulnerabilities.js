/* Vulnerabilities — the findings table plus the per-finding investigation view.
 *
 * The investigation view is the product's core: deterministic verdict first,
 * then evidence, then reachability path, then provenance, then artifacts.
 * Fields the engine did not emit are printed as "Not available".
 */

import { el, frag, shorten } from "../dom.js";
import {
  badge, button, callout, chainCompact, chainList, dataTable, evidenceList, gradeBadge,
  kvList, mono, notAvailable, panel, reachabilityBadge, riskAssessmentPanel, severityBadge,
  stateBlock, trustBadge, trustFacts, verdictBadge,
} from "../components.js";
import { SEVERITY_ORDER, packageIndex, reachabilityStateOf } from "../model.js";
import {
  cvssBreakdown, fmtDateTime, justificationText, num, purlParts, reachabilityOf,
} from "../format.js";
import { analysisGate, countLabel, pageHead, usePaged, useSort } from "./common.js";

const REACHABILITY_OPTIONS = [
  ["", "Any reachability"],
  ["calls-found", "Calls found (reachable)"],
  ["no-calls", "Imported, no calls found"],
  ["not-imported", "Not imported"],
  ["unknown", "Unknown"],
];

function severityToggle(band, active, onClick) {
  const node = el("button", {
    type: "button",
    class: `badge badge--${band}${active ? "" : " badge--plain"}`,
    "aria-pressed": active ? "true" : "false",
    style: { cursor: "pointer", background: active ? undefined : "transparent" },
    title: `Toggle ${band} findings`,
    onclick: onClick,
  }, el("span", { class: "glyph", "aria-hidden": "true", text: { critical: "◆", high: "▲",
    medium: "●", low: "▬", unknown: "○" }[band] }), band.toUpperCase());
  return node;
}

function filterBar(ctx, { severity, verdict, reachability, ecosystem, actionability }) {
  const setUi = ctx.setUi;
  const ecosystems = [...ctx.analysis.ecosystemCounts.keys()].sort();
  const toggleSeverity = (band) => {
    const next = new Set(severity);
    if (next.has(band)) next.delete(band); else next.add(band);
    setUi({ filters: { severity: [...next] }, page: 1 });
  };
  return el("div", { class: "toolbar" },
    ctx.searchControl(),
    el("div", { class: "field-inline", role: "group", "aria-label": "Severity filter" },
      SEVERITY_ORDER.map((band) => severityToggle(band, severity.includes(band), () => toggleSeverity(band)))),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Verdict" }),
      el("select", { value: verdict, "aria-label": "Verdict filter",
                     onchange: (event) => setUi({ filters: { verdict: event.target.value }, page: 1 }) },
        [["", "Any verdict"], ["affected", "Actionable (affected)"],
         ["not_affected", "Not affected"]].map(([value, label]) => el("option", {
          value, selected: value === verdict ? true : null, text: label })))),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Reachability" }),
      el("select", { value: reachability, "aria-label": "Reachability filter",
                     onchange: (event) => setUi({ filters: { reachability: event.target.value }, page: 1 }) },
        REACHABILITY_OPTIONS.map(([value, label]) => el("option", {
          value, selected: value === reachability ? true : null, text: label })))),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Ecosystem" }),
      el("select", { value: ecosystem, "aria-label": "Ecosystem filter",
                     onchange: (event) => setUi({ filters: { ecosystem: event.target.value }, page: 1 }) },
        [["", "All ecosystems"], ...ecosystems.map((name) => [name, name])].map(([value, label]) => el("option", {
          value, selected: value === ecosystem ? true : null, text: label })))),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Show" }),
      el("select", { value: actionability, "aria-label": "Actionability filter",
                     onchange: (event) => setUi({ filters: { actionability: event.target.value }, page: 1 }) },
        [["", "Everything"], ["actionable", "Actionable only"],
         ["unreachable", "Unreachable only"]].map(([value, label]) => el("option", {
          value, selected: value === actionability ? true : null, text: label })))),
    actionability || verdict || reachability || ecosystem || severity.length
      ? button("Clear filters", { onClick: () => ctx.setUi({ filters: {}, query: "", page: 1 }),
                                  variant: "quiet" })
      : null);
}

export function render(ctx) {
  const gate = analysisGate(ctx);
  const { analysis } = ctx;
  const head = pageHead({
    title: "Vulnerabilities",
    sub: "Every advisory returned for this inventory, with the engine's verdict and the evidence behind it",
    actions: analysis ? [
      button("Reports", { onClick: () => ctx.actions.navigate("reports"), variant: "quiet" }),
    ] : [],
  });
  if (gate) return frag(head, el("div", { style: { marginTop: "var(--sp-4)" } }, gate));

  const filters = ctx.ui.filters || {};
  const severity = filters.severity || [];
  const verdict = filters.verdict || "";
  const reachability = filters.reachability || "";
  const ecosystem = filters.ecosystem || "";
  const actionability = filters.actionability || "";

  const rows = ctx.filterFindings(analysis.findings, {
    query: ctx.ui.query || "", severity, verdict, reachability, ecosystem, actionability,
  });
  const { sort, onSort } = useSort(ctx.ui, ctx.setUi, { key: "severity", dir: "asc" });
  const sorted = ctx.sortedFindings(rows, sort);
  const paged = usePaged(sorted, ctx.ui, ctx.setUi, 25);
  const index = packageIndex(analysis);

  const columns = [
    { key: "severity", label: "Severity", sortable: true,
      render: (finding) => severityBadge(finding.severity) },
    { key: "package", label: "Package", sortable: true,
      render: (finding) => el("span", { class: "pkg", text: finding.packageName }) },
    { key: "version", label: "Version", sortable: true, class: "cell-mono",
      render: (finding) => finding.packageVersion },
    { key: "id", label: "Vulnerability", sortable: true,
      render: (finding) => el("div", {},
        el("div", { class: "cell-mono", text: finding.id }),
        finding.aliases.length ? el("div", { class: "field-hint",
          text: shorten(finding.aliases.join(", "), 40) }) : null) },
    { key: "verdict", label: "Verdict", sortable: true, render: (finding) => verdictBadge(finding) },
    { key: "reachability", label: "Reachability", sortable: true,
      render: (finding) => reachabilityBadge(finding) },
    { key: "path", label: "Evidence path", render: (finding) => chainCompact(ctx.pathFor(finding)) },
    { key: "trust", label: "Trust", render: (finding) => trustBadge(index.find(finding.package)) },
    { key: "fixed", label: "Fixed in", sortable: true, class: "cell-mono",
      render: (finding) => finding.fixedVersion || notAvailable("—") },
    { key: "action", label: "", class: "cell-actions",
      render: (finding) => button("Investigate", { variant: "quiet",
        onClick: (event) => { event.stopPropagation(); ctx.actions.openFinding(finding.key); } }) },
  ];

  return frag(
    head,
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Findings",
        note: countLabel(paged.total, analysis.findings.length, "advisories"),
        flush: true,
        body: frag(
          filterBar(ctx, { severity, verdict, reachability, ecosystem, actionability }),
          dataTable({
            columns, rows: paged.rows, sort, onSort,
            rowClass: (finding) => `row-sev-${finding.band}`,
            onRowClick: (finding) => ctx.actions.openFinding(finding.key),
            empty: el("div", { style: { padding: "var(--sp-4)" } },
              stateBlock({ tone: "idle", mark: "∅",
                title: analysis.findings.length ? "No finding matches these filters" : "No advisories in this scan",
                body: analysis.findings.length
                  ? "Relax the filters to see the rest of the report. Filtering never changes a verdict."
                  : "The engine's advisory lookup returned nothing for this inventory. An empty table is "
                    + "not a safety guarantee — check the dependency inventory and the unresolved "
                    + "dependency list for what was actually queried.",
                actions: [button("Reset filters", { onClick: () => ctx.setUi({ filters: {}, query: "" }) })] })),
          }),
          paged.pager),
        foot: [
          el("span", { text: "Verdicts and justifications are produced by the deterministic engine and are "
            + "never re-derived in the browser." }),
        ],
      })));
}

/* ---- investigation view (drawer content) --------------------------------- */

function verdictBanner(finding) {
  const verdict = finding.actionable ? "affected" : finding.status === "not_affected" ? "not_affected" : "unknown";
  const note = finding.actionable
    ? "The engine found a call to an advisory-identified function in this repository."
    : justificationText(finding.justification) || "The engine recorded no actionable path.";
  return el("div", { class: "verdict-banner", dataset: { verdict } },
    el("div", {},
      el("div", { class: "verdict-word", text: finding.actionable ? "ACTIONABLE" : "NOT AFFECTED" }),
      el("div", { class: "verdict-note", text: note })),
    el("div", { style: { marginLeft: "auto" } }, severityBadge(finding.severity)),
    gradeBadge(finding.evidence?.function_source));
}

function recommendedAction(finding) {
  if (finding.actionable) {
    return finding.fixedVersion
      ? `Upgrade ${finding.packageName} to ${finding.fixedVersion} or later, and re-run the scan to `
        + "confirm the call site disappears. A matched call is a strong signal, not proof of "
        + "exploitability: review how the function is used and whether untrusted input reaches it."
      : "No fixed version was reported by the advisory, so there is nothing to upgrade to. Reduce the "
        + "exposure of the call site (avoid the advisory function, or pin/remove the dependency), then "
        + "re-run the scan; the report records the call site so the decision is auditable.";
  }
  const grade = finding.evidence?.function_source;
  const caveat = grade && String(grade).includes("llm")
    ? " The vulnerable-function list was LLM-assisted (unioned with advisory text), so re-verify if the "
      + "call path or the advisory changes."
    : grade === "conservative-default"
      ? " No function-level data was available for this advisory, and the engine still treated the finding "
        + "as actionable."
      : "";
  return "No action is required by the reachability analysis: the OpenVEX statement below records the "
    + `justification (${finding.justification || "not reported"}), so downstream tooling can consume the `
    + "decision instead of re-triaging it." + caveat;
}

export function renderFinding(ctx, finding) {
  const analysis = ctx.analysis;
  const path = ctx.pathFor(finding);
  const reach = reachabilityOf(finding);
  const index = packageIndex(analysis);
  const pkg = index.find(finding.package);
  const locations = [...reach.calls, ...reach.imports].filter((item) => item && item.file);

  return frag(
    panel({
      title: "Verdict",
      body: [
        verdictBanner(finding),
        finding.impactStatement
          ? el("p", { class: "panel-note", style: { marginTop: "var(--sp-3)" }, text: finding.impactStatement })
          : null,
        el("div", { class: "section-title", text: "Identity" }),
        kvList([
          ["Vulnerability", finding.id, { mono: true }],
          ["Aliases", finding.aliases.length ? finding.aliases.join(", ") : null, { mono: true }],
          ["Package", `${finding.packageName} @ ${finding.packageVersion}`],
          ["Ecosystem", finding.ecosystem],
          ["Package URL", finding.purl, { mono: true, breakAll: true }],
          ["Fixed version", finding.fixedVersion,
            { mono: true, missing: "the advisory reported no fixed version" }],
          ["Affected range", null,
            { missing: "this engine does not emit affected-version ranges — only the installed version and the advisory's fixed version" }],
          ["Severity basis", finding.severity.basis],
        ]),
      ],
    }),

    panel({
      title: "Severity",
      note: finding.severity.computed ? "base score computed from the advisory vector" : "as reported by the advisory",
      body: [
        el("div", { class: "field-inline" },
          severityBadge(finding.severity),
          el("span", { class: "field-hint", text: finding.severity.basis })),
        finding.severity.vector
          ? el("div", { style: { marginTop: "var(--sp-3)" } },
              kvList([["Vector", finding.severity.vector, { mono: true, breakAll: true }]]),
              (() => {
                const parts = cvssBreakdown(finding.severity.vector);
                return parts.length
                  ? el("div", { class: "section-title", text: "Vector metrics" },
                      kvList(parts.map((part) => [part.key, part.text])))
                  : null;
              })())
          : el("p", { class: "field-hint", style: { marginTop: "var(--sp-2)" },
                      text: "The advisory carried no CVSS vector or numeric score, so no severity band is shown." }),
        finding.severity.sources?.length > 1
          ? el("p", { class: "field-hint", style: { marginTop: "var(--sp-2)" },
            text: `Advisory entries: ${finding.severity.sources.map((source) =>
              `${source.type}=${typeof source.score === "string" ? shorten(source.score, 32) : source.score}`).join(" · ")}` })
          : null,
      ].filter(Boolean),
    }),

    panel({
      title: "Reachability path",
      note: "built from the engine's import/call evidence",
      body: [chainList(path), el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
        text: `Evidence basis: ${path.grade.word} — ${path.grade.note}. `
          + "The engine's own decision source is shown verbatim so an LLM-assisted hint is never "
          + "mistaken for a deterministic check." })],
    }),

    panel({
      title: "Evidence",
      note: locations.length ? `${locations.length} source location(s)` : null,
      body: [
        el("div", { class: "section-title", text: "Vulnerable functions from the advisory" }),
        reach.functions.length
          ? el("div", { class: "field-inline" }, reach.functions.map((name) => badge(name, "info", { plain: true })))
          : notAvailable("the advisory text named no function"),
        reach.confidence !== null && reach.confidence !== undefined
          ? el("p", { class: "field-hint", style: { marginTop: "var(--sp-2)" },
            text: `LLM-reported confidence for the function list: ${num(reach.confidence)}` })
          : null,
        el("div", { class: "section-title", text: "Import / require sites" }),
        evidenceList(reach.imports),
        el("div", { class: "section-title", text: "Calls to advisory functions" }),
        evidenceList(reach.calls),
      ],
    }),

    panel({
      title: "Description",
      body: [
        finding.summary ? el("p", { class: "state-body", text: finding.summary }) : null,
        finding.details
          ? el("pre", { class: "code-block", text: finding.details })
          : notAvailable("the advisory carried no details"),
      ],
    }),

    panel({
      title: "Recommended action",
      note: "derived from the verdict, not a new security decision",
      body: [el("p", { class: "state-body", text: recommendedAction(finding) })],
    }),

    panel({
      title: "Machine-readable statement",
      note: "OpenVEX as written by the engine",
      body: finding.vex
        ? [kvList([
            ["Status", finding.vex.status],
            ["Justification", finding.vex.justification || null],
            ["Product matches this purl", finding.vexMatches === null ? null : String(finding.vexMatches)],
          ]),
          el("pre", { class: "code-block", style: { marginTop: "var(--sp-3)" },
                      text: JSON.stringify(finding.vex, null, 2) })]
        : [notAvailable("no OpenVEX statement matched this finding id")],
    }),

    panel({
      title: "Trace and trust provenance",
      note: "where this finding came from",
      body: [
        kvList([
          ["Scan id", analysis.scanId, { mono: true, breakAll: true }],
          ["Repository id", analysis.repositoryId, { mono: true }],
          ["Engine run", analysis.runMetadata?.timestamp ? fmtDateTime(analysis.runMetadata.timestamp) : null],
        ]),
        el("div", { class: "section-title", text: "Trust signals for this package" }),
        pkg
          ? kvList(trustFacts(pkg).map(([label, value]) => [label, value, { mono: true }]))
          : notAvailable("this finding's package is not in the scanned inventory"),
        el("p", { class: "field-hint", style: { marginTop: "var(--sp-2)" },
          text: "Signals the engine does not produce yet (signatures, provenance attestations, maintainer "
            + "history) are listed as planned capabilities on the Trust page rather than guessed here." }),
        el("p", { class: "field-hint",
          text: "Raw report entry is included below so every claim on this screen can be checked against "
            + "the engine's own output." }),
        el("div", { style: { marginTop: "var(--sp-3)" } },
          button("Open raw artifacts", { onClick: () => ctx.actions.navigate("reports"), variant: "quiet" })),
      ],
    }),

    // Future ML: renders only when the scan data carries a real model result
    // (pipeline order is verdict → evidence → reachability → trust → ML risk).
    riskAssessmentPanel(finding),

    panel({
      title: "Raw report entry",
      note: "exactly as report.json records it",
      body: [el("pre", { class: "code-block", text: JSON.stringify(finding.raw, null, 2) }),
             el("p", { class: "field-hint", text: `Trace reference: ${purlParts(finding.purl).type || "unknown"}`
               + ` · ${finding.id} · scan ${analysis.scanId || "unknown"}` })],
    }));
}

export { reachabilityStateOf };

/* Reachability — why an advisory is, or is not, on an execute path.
 *
 * This page visualises the engine's own reachability evidence. Nothing is
 * recalculated here: `reachabilityPath()` turns the recorded import sites, call
 * sites, advisory functions and justification into a path, and the verdict
 * shown next to it is the verdict from report.json.
 */

import { el, frag, shorten } from "../dom.js";
import {
  button, callout, chainList, dataTable, gradeBadge, notAvailable, panel,
  reachabilityPath, severityBadge, stateBlock, verdictBadge,
} from "../components.js";
import { reachabilityStateOf, sortFindings } from "../model.js";
import { gradeOf, num, reachabilityOf } from "../format.js";
import { analysisGate, countLabel, metricStrip, pageHead, usePaged } from "./common.js";

const STATE_LABEL = {
  "calls-found": "Reachable — a call to an advisory function was found",
  "no-calls": "Imported, no call found",
  "not-imported": "Dependency never imported",
  unknown: "No function-level data",
};

/** Every decision source this engine version can record, with its grade. */
const DECISION_SOURCES = [
  "import-check", "advisory_backticks", "heuristic", "llm", "llm+advisory_backticks",
  "conservative-default",
];

function selectField({ label, value, options, onChange }) {
  return el("label", { class: "field" },
    el("span", { class: "field-hint", text: label }),
    el("select", { value, "aria-label": label, onchange: (event) => onChange(event.target.value) },
      options.map(([optionValue, optionLabel]) => el("option", {
        value: optionValue, selected: optionValue === value ? true : null, text: optionLabel }))));
}

function filterRow(ctx, filters) {
  const state = filters.state || "";
  const severity = filters.severity || "";
  return el("div", { class: "toolbar" },
    ctx.searchControl(),
    selectField({
      label: "Reachability", value: state,
      options: [["", "Any reachability"], ...Object.entries(STATE_LABEL)],
      onChange: (value) => ctx.setUi({ filters: { ...filters, state: value }, page: 1 }),
    }),
    selectField({
      label: "Severity", value: severity,
      options: [["", "Any severity"], ["critical", "Critical"], ["high", "High"],
                ["medium", "Medium"], ["low", "Low"], ["unknown", "Unrated"]],
      onChange: (value) => ctx.setUi({ filters: { ...filters, severity: value }, page: 1 }),
    }),
    state || severity
      ? button("Clear filters", { onClick: () => ctx.setUi({ filters: {}, query: "", page: 1 }),
                                  variant: "quiet" })
      : null);
}

/** One finding: its path, its verdict and how much evidence stands behind it. */
function evidenceCard(ctx, finding) {
  const path = reachabilityPath(finding, ctx.analysis);
  const reach = reachabilityOf(finding);
  const counts = [
    `${num(reach.imports.length)} import site(s)`,
    `${num(reach.calls.length)} call site(s)`,
    reach.functions.length
      ? `${num(reach.functions.length)} advisory function(s): ${shorten(reach.functions.join(", "), 60)}`
      : "the advisory named no function",
  ].join(" · ");

  return panel({
    title: finding.id,
    note: `${finding.packageName} @ ${finding.packageVersion} · ${finding.ecosystem}`,
    actions: [
      severityBadge(finding.severity),
      verdictBadge(finding),
      gradeBadge(finding.evidence?.function_source),
      button("Open investigation", { onClick: () => ctx.actions.openFinding(finding.key),
                                     variant: "quiet" }),
    ],
    body: [
      chainList(path),
      el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" }, text: counts }),
      finding.aliases.length
        ? el("p", { class: "field-hint", text: `Aliases: ${finding.aliases.join(", ")}` })
        : null,
    ].filter(Boolean),
  });
}

/** trace.json records one journey per package; show the one being inspected. */
function journeyPanel(ctx, findings) {
  const journeys = ctx.analysis.journeys || [];
  if (!journeys.length) {
    return panel({
      title: "Package journey",
      note: "recorded in trace.json",
      body: [stateBlock({ tone: "idle", mark: "?", title: "No journey recorded",
        body: "trace.json was either not loaded for this scan or carried no per-package events. "
          + "Journeys are a record of the pipeline, not a security conclusion, so nothing is "
          + "reconstructed here." })],
    });
  }
  const keys = journeys.map((journey) => journey.purl || journey.package);
  const selectedKey = ctx.ui.journey && keys.includes(ctx.ui.journey)
    ? ctx.ui.journey
    : (() => {
        const first = findings[0];
        const match = first && journeys.find((journey) => journey.purl === first.purl
          || journey.package === first.packageName);
        return match ? (match.purl || match.package) : keys[0];
      })();
  const journey = journeys.find((item) => (item.purl || item.package) === selectedKey) || journeys[0];

  return panel({
    title: "Package journey",
    note: `${num(journeys.length)} package journey(s) recorded in trace.json`,
    actions: [
      el("label", { class: "field" },
        el("span", { class: "field-hint", text: "Package" }),
        el("select", { value: selectedKey, "aria-label": "Package journey",
                       onchange: (event) => ctx.setUi({ journey: event.target.value, page: 1 }) },
          journeys.map((item) => {
            const key = item.purl || item.package;
            return el("option", { value: key, selected: key === selectedKey ? true : null,
                                  text: `${item.package} (${(item.events || []).length} events)` });
          }))),
    ],
    body: [
      el("p", { class: "panel-note",
                text: `Journey for ${journey.package}${journey.purl ? ` · ${journey.purl}` : ""}` }),
      el("div", { style: { marginTop: "var(--sp-3)" } },
        dataTable({
          columns: [
            { key: "stage", label: "Stage", render: (row) => el("span", { class: "cell-mono",
              text: row.stage || "unknown" }) },
            { key: "result", label: "Result", render: (row) => el("span", { class: "cell-mono",
              text: row.result || "unknown" }) },
            { key: "detail", label: "Detail", render: (row) => {
              const text = row.detail === null || row.detail === undefined
                ? "" : (typeof row.detail === "string" ? row.detail : JSON.stringify(row.detail));
              return text
                ? el("span", { class: "chain-detail", text: shorten(text, 96),
                               title: typeof row.detail === "string" ? row.detail
                                 : JSON.stringify(row.detail, null, 2) })
                : notAvailable("no detail recorded");
            } },
          ],
          rows: journey.events || [],
          empty: el("span", { class: "field-hint", text: "this journey carried no events" }),
        })),
    ],
  });
}

function gradingPanel() {
  return panel({
    title: "How to read these grades",
    note: "the engine's decision source, as written in report.json",
    body: [
      el("p", { class: "state-body",
        text: "Reachability is static and best effort. The grade on each card is the engine's own "
          + "decision source, mapped to words — it is never upgraded in the browser:" }),
      el("div", { style: { marginTop: "var(--sp-3)" } },
        el("div", { class: "kv" }, DECISION_SOURCES.flatMap((source) => {
          const grade = gradeOf(source);
          return [
            el("dt", {}, el("span", { class: "cell-mono", text: source })),
            el("dd", {}, gradeBadge(source), el("span", { class: "chain-detail",
              style: { marginLeft: "var(--sp-2)" }, text: grade.note })),
          ];
        }))),
      el("div", { style: { marginTop: "var(--sp-4)" } },
        callout("info", "What this engine version does not provide",
          "Richer evidence grades beyond this decision source — for example a formal "
          + "CONFIRMED / INFERRED / UNKNOWN scale with confidence intervals — do not exist in this "
          + "build, so none is displayed. This view is structured so that a future `evidence_grade` "
          + "field can be rendered beside the existing badges without redesigning the page.")),
      el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
        text: "A matched call site is strong evidence that vulnerable code is on an execute path, and "
          + "a missing call is evidence against it; neither is proof of exploitability, because the "
          + "analysis cannot see reflection, dynamic dispatch, wrappers or native code." }),
    ],
  });
}

export function render(ctx) {
  const gate = analysisGate(ctx);
  const { analysis } = ctx;
  const head = pageHead({
    title: "Reachability",
    sub: "Why each advisory is or is not on an execute path, from the engine's own import and call evidence",
    actions: analysis ? [
      button("All vulnerabilities", { onClick: () => ctx.actions.navigate("vulnerabilities"),
                                      variant: "quiet" }),
    ] : [],
  });
  if (gate) return frag(head, el("div", { style: { marginTop: "var(--sp-4)" } }, gate));

  const findings = analysis.findings;
  const counts = { "calls-found": 0, "no-calls": 0, "not-imported": 0, unknown: 0 };
  for (const finding of findings) counts[reachabilityStateOf(finding)] += 1;

  const filters = ctx.ui.filters || {};
  const rows = findings.filter((finding) => {
    if (filters.state && reachabilityStateOf(finding) !== filters.state) return false;
    if (filters.severity && finding.band !== filters.severity) return false;
    if (ctx.ui.query) {
      const needle = ctx.ui.query.trim().toLowerCase();
      const haystack = [finding.id, finding.aliases.join(" "), finding.packageName,
                        finding.summary, finding.packageVersion].join(" ").toLowerCase();
      if (!haystack.includes(needle)) return false;
    }
    return true;
  });
  // Reachable findings first: a call site needs attention, a missing import does not.
  const sorted = sortFindings(rows, { key: "severity", dir: "asc" });
  const ordered = [...sorted.filter((finding) => finding.actionable),
                   ...sorted.filter((finding) => !finding.actionable)];
  const paged = usePaged(ordered, ctx.ui, ctx.setUi, 10);

  return frag(
    head,
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Reachability across this scan",
        note: "counts derived from the recorded import and call evidence",
        body: [
          metricStrip([
            { value: num(counts["calls-found"]), label: "Reachable",
              tone: counts["calls-found"] ? "bad" : "ok",
              note: "a call to an advisory function was found" },
            { value: num(counts["no-calls"]), label: "Imported, not called", tone: "ok",
              note: "imported, but no advisory function is called" },
            { value: num(counts["not-imported"]), label: "Never imported", tone: "ok",
              note: "the dependency is absent from the scanned source" },
            { value: num(counts.unknown), label: "No function data", tone: "warn",
              note: "the advisory named no function to test for" },
          ]),
          el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
            text: "Findings in the last group are the conservative default: when no function-level "
              + "data is available the engine keeps the vulnerability actionable rather than "
              + "dismissing it, so an empty function list never looks like safety." }),
        ],
      })),

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Evidence paths",
        note: countLabel(paged.total, findings.length, "advisories"),
        flush: true,
        body: frag(
          filterRow(ctx, filters),
          paged.rows.length
            ? el("div", { style: { padding: "var(--sp-4)", display: "flex",
                                   flexDirection: "column", gap: "var(--sp-4)" } },
                paged.rows.map((finding) => evidenceCard(ctx, finding)))
            : el("div", { style: { padding: "var(--sp-4)" } },
                stateBlock({ tone: "idle", mark: "∅",
                  title: "No finding matches these filters",
                  body: "Relax the filters to see the rest of the report. Filtering only hides rows: "
                    + "it never changes a verdict or an evidence grade.",
                  actions: [button("Reset filters", { onClick: () => ctx.setUi({ filters: {}, query: "" }) })] })),
          paged.pager),
        foot: [el("span", { text: "Paths come from static analysis: dynamic imports, reflection, "
          + "wrappers and native code can hide a real path, and a match can be a false positive." })],
      })),

    el("div", { style: { marginTop: "var(--sp-4)" } }, journeyPanel(ctx, ordered)),
    el("div", { style: { marginTop: "var(--sp-4)" } }, gradingPanel()));
}

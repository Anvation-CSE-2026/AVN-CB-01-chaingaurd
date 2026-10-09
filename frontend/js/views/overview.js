/* Overview — security posture from the real scan result.
 *
 * Every number printed here comes from the engine's own summary or from the
 * detailed findings in the same response; the consistency check flags a
 * disagreement instead of picking a favourite.
 */

import { el, frag, shorten } from "../dom.js";
import {
  button, callout, chainCompact, dataTable, kvList, mono, panel, postureMeter,
  reachabilityBadge, severityBadge, stateBlock, stepsStrip, trustBadge, verdictBadge,
} from "../components.js";
import { STAGE_LABELS, packageIndex } from "../model.js";
import { durationMs, num, pct, fmtDateTime } from "../format.js";
import { analysisGate, pageHead, usePaged, useSort } from "./common.js";

function findingColumns(ctx) {
  const index = packageIndex(ctx.analysis);
  return [
    { key: "package", label: "Package", sortable: true,
      render: (finding) => el("span", { class: "pkg", text: finding.packageName }) },
    { key: "version", label: "Version", sortable: true, class: "cell-mono",
      render: (finding) => finding.packageVersion },
    { key: "id", label: "Vulnerability", sortable: true,
      render: (finding) => el("span", { class: "cell-mono", text: finding.id,
                                       title: finding.summary || finding.id }) },
    { key: "severity", label: "Severity", sortable: true, render: (finding) => severityBadge(finding.severity) },
    { key: "reachability", label: "Reachability", sortable: true,
      render: (finding) => reachabilityBadge(finding) },
    { key: "verdict", label: "Verdict", sortable: true, render: (finding) => verdictBadge(finding) },
    { key: "trust", label: "Trust",
      render: (finding) => trustBadge(index.find(finding.package)) },
    { key: "path", label: "Path", render: (finding) => chainCompact(ctx.pathFor(finding)) },
    { key: "action", label: "", class: "cell-actions",
      render: (finding) => button("Investigate", { onClick: (event) => {
        event.stopPropagation();
        ctx.actions.openFinding(finding.key);
      }, variant: "quiet" }) },
  ];
}

function riskSummary(analysis) {
  const byBand = new Map();
  for (const finding of analysis.findings) {
    if (!finding.actionable) continue;
    byBand.set(finding.band, (byBand.get(finding.band) || 0) + 1);
  }
  const order = ["critical", "high", "medium", "low", "unknown"];
  const actionRows = order.filter((band) => byBand.get(band)).map((band) => el("div",
    { class: "status-line" },
    el("span", { class: `v${band === "critical" || band === "high" ? " is-bad" : ""}`,
                 style: { minWidth: "64px" }, text: num(byBand.get(band)) }),
    el("span", { class: "k", text: band === "unknown" ? "unrated" : band })));

  const suspicious = analysis.packages.filter((pkg) => pkg.registry?.suspicious);
  const unresolvedRegistry = analysis.packages.filter((pkg) => pkg.registry?.lookupError);

  return panel({
    title: "Risk summary",
    note: "counts are the engine's verdicts for this scan",
    body: [
      el("div", {},
        el("div", { class: "stack" },
          el("div", { class: "kv" },
            el("dt", { text: "Actionable" }),
            el("dd", {}, actionRows.length ? actionRows
              : el("span", { class: "field-hint", text: "none — no finding is reachable" })),
            el("dt", { text: "Suspicious packages" }),
            el("dd", {}, suspicious.length
              ? suspicious.map((pkg) => el("div", { class: "status-line" },
                  el("span", { class: "k", text: `${pkg.name}@${pkg.version}` }),
                  el("span", { class: "v is-bad",
                               text: pkg.registry.reasons.join("; ") || pkg.registry.status || "flagged" })))
              : el("span", { class: "field-hint", text: "none flagged by registry checks" })),
            el("dt", { text: "Unreachable advisories" }),
            el("dd", {}, el("span", { class: "field-hint",
              text: `${num(analysis.summaryCounts.unreachable)} dismissed with a justification` })),
            el("dt", { text: "Registry lookups failed" }),
            el("dd", {}, unresolvedRegistry.length
              ? el("span", { class: "field-hint",
                  text: `${num(unresolvedRegistry.length)} package(s) could not be verified — an unavailable lookup is reported as unknown, never as safe` })
              : el("span", { class: "field-hint", text: "none — every package version was looked up" }))),
          el("div", {},
            el("h3", { class: "panel-title", text: "Where the noise went" }),
            el("p", { class: "panel-note", style: { marginTop: "var(--sp-2)" },
              text: `${num(analysis.summaryCounts.unreachable)} of ${num(analysis.summaryCounts.total)} `
                + `advisories were kept in the report but dismissed as unreachable `
                + `(${pct(analysis.summaryCounts.noiseReduced)} noise reduction). `
                + "Nothing was deleted: each dismissal carries an OpenVEX justification and follows the "
                + "reachability path shown per finding." })))),
      analysis.unresolved.length
        ? callout("warn", `${analysis.unresolved.length} unresolved dependency declaration(s)`,
            "These manifest entries had no single exact version (ranged, wildcard, placeholder or "
            + "unparseable), so no advisory lookup was possible for them. The engine discloses them "
            + "rather than dropping them — a scan cannot silently look clean.")
        : null,
    ],
  });
}

function pipelinePanel(analysis) {
  const stages = analysis.stages;
  const recorded = stages.length;
  return panel({
    title: "Evidence pipeline",
    note: recorded ? `${recorded} stages recorded in trace.json` : "trace.json not loaded",
    body: recorded
      ? [
          stepsStrip(STAGE_LABELS, { completedThrough: recorded - 1 }),
          el("div", { style: { marginTop: "var(--sp-4)" } },
            dataTable({
              columns: [
                { key: "stage", label: "Stage", render: (row) => mono(row.stage) },
                { key: "items", label: "Items", align: "right",
                  render: (row) => `${num(row.items_in)} → ${num(row.items_out)}` },
                { key: "ms", label: "Duration", align: "right", render: (row) => durationMs(row.duration_ms) },
              ],
              rows: stages,
            })),
        ]
      : [stateBlock({ tone: "idle", mark: "?", title: "Stage timing unavailable",
          body: "trace.json could not be read for this scan, so the per-stage pipeline is not shown. "
            + "Findings above are unaffected: they come from report.json." })],
  });
}

function provenancePanel(ctx) {
  const { analysis, state } = ctx;
  const artifacts = analysis.artifacts || {};
  const loaded = analysis.artifactsLoaded || {};
  const metadata = analysis.runMetadata || {};
  const flags = metadata.flags || {};
  return panel({
    title: "Run provenance",
    note: "how this result was produced",
    body: [
      analysis.reconstructed
        ? callout("info", "Reopened from artifacts",
            "The API stores no scan index, so this run was rebuilt from its four artifact files. "
            + "The engine's exit code is unknown and is shown as not available; everything else comes "
            + "from report.json and trace.json exactly as written.")
        : null,
      kvList([
        ["Scan id", analysis.scanId, { mono: true, breakAll: true }],
        ["Repository id", analysis.repositoryId, { mono: true }],
        ["Target path", analysis.target, { mono: true, breakAll: true }],
        ["API status", analysis.status],
        ["Engine state", analysis.state],
        ["Engine exit code", analysis.scan?.exit_code ?? null],
        ["Engine duration", analysis.scan?.duration_ms === undefined ? null : durationMs(analysis.scan.duration_ms)],
        ["Engine version", metadata.tool_version || null],
        ["Python version", metadata.python_version || null],
        ["Run timestamp", metadata.timestamp ? fmtDateTime(metadata.timestamp) : null],
        ["Flags", Object.keys(flags).length
          ? Object.entries(flags).map(([key, value]) => `${key}=${value}`).join("  ")
          : null],
      ]),
      el("div", { class: "section-title", text: "Artifacts" }),
      el("div", { class: "status-line" },
        el("span", { class: "k", text: "report.json" }),
        el("span", { class: `v ${loaded.report ? "is-ok" : "is-bad"}`,
                     text: loaded.report ? "loaded" : (analysis.artifactErrors?.report?.code || "missing") })),
      el("div", { class: "status-line" },
        el("span", { class: "k", text: "trace.json" }),
        el("span", { class: `v ${loaded.trace ? "is-ok" : "is-warn"}`,
                     text: loaded.trace ? "loaded" : (analysis.artifactErrors?.trace?.code || "missing") })),
      el("div", { class: "status-line" },
        el("span", { class: "k", text: "sbom.cdx.json" }),
        el("span", { class: `v ${loaded.sbom ? "is-ok" : "is-warn"}`,
                     text: loaded.sbom ? `loaded (${(analysis.sbomMetadata?.tools?.components || [])
                       .map((tool) => `${tool.name}@${tool.version}`).join(", ") || "unknown tool"})`
                       : (analysis.artifactErrors?.sbom?.code || "missing") })),
      el("div", { class: "status-line" },
        el("span", { class: "k", text: "openvex.json" }),
        el("span", { class: `v ${loaded.vex ? "is-ok" : "is-warn"}`,
                     text: loaded.vex ? `loaded (${num(analysis.findings.filter((f) => f.vex).length)} statements matched)`
                       : (analysis.artifactErrors?.vex?.code || "missing") })),
      el("div", { style: { marginTop: "var(--sp-3)" } },
        button("Open reports", { onClick: () => ctx.actions.navigate("reports"), variant: "quiet" })),
    ],
  });
}

export function render(ctx) {
  const gate = analysisGate(ctx);
  const { analysis, posture } = ctx;
  const head = pageHead({
    title: "Overview",
    sub: analysis
      ? `${analysis.label} · ${analysis.target || "unknown target"}`
      : "Security posture for the most recent ChainGuard scan",
    actions: [
      button("Run scan", { onClick: () => ctx.actions.navigate("scans"), variant: "primary" }),
      analysis ? button("Open reports", { onClick: () => ctx.actions.navigate("reports") }) : null,
    ].filter(Boolean),
  });

  if (gate) return frag(head, el("div", { style: { marginTop: "var(--sp-4)" } }, gate));

  const actionable = analysis.findings.filter((finding) => finding.actionable);
  const unreachable = analysis.findings.filter((finding) => !finding.actionable);
  const { sort, onSort } = useSort(ctx.ui, ctx.setUi, { key: "severity", dir: "asc" });
  const reordered = ctx.sortedFindings(actionable, sort);
  const paged = usePaged(reordered.slice(0, 50), ctx.ui, ctx.setUi, 10);

  return frag(
    head,
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({ title: "Security posture", note: "derived from the engine's summary, not a model score",
              body: postureMeter(posture, analysis) })),

    el("div", { class: "split", style: { marginTop: "var(--sp-4)" } },
      el("div", {},
        panel({
          title: "Top risks",
          note: `${num(actionable.length)} actionable finding(s)`,
          flush: true,
          actions: [button("All vulnerabilities", { onClick: () => ctx.actions.navigate("vulnerabilities") })],
          body: actionable.length
            ? frag(
                dataTable({
                  columns: findingColumns(ctx),
                  rows: paged.rows,
                  sort, onSort,
                  rowClass: (finding) => `row-sev-${finding.band}`,
                  onRowClick: (finding) => ctx.actions.openFinding(finding.key),
                  caption: "Reachable findings — a call to an advisory-identified function was found",
                }),
                paged.pager)
            : el("div", { style: { padding: "var(--sp-4)" } },
                callout("ok", "No actionable findings",
                  "For this scan every advisory the engine queried was dismissed as unreachable, "
                  + "and no suspicious package was flagged. This is the engine's deterministic verdict, "
                  + "not a guarantee of safety.")),
        }),
        panel({
          title: "Dismissed as unreachable",
          note: `${num(unreachable.length)} finding(s) kept in the report`,
          flush: true,
          actions: [button("Open reachability", { onClick: () => ctx.actions.navigate("reachability") })],
          body: unreachable.length
            ? dataTable({
                columns: [
                  { key: "package", label: "Package", render: (finding) => el("span", { class: "pkg",
                    text: finding.packageName }) },
                  { key: "version", label: "Version", class: "cell-mono",
                    render: (finding) => finding.packageVersion },
                  { key: "id", label: "Vulnerability", render: (finding) => el("span", { class: "cell-mono",
                    text: finding.id }) },
                  { key: "severity", label: "Severity", render: (finding) => severityBadge(finding.severity, { showScore: false }) },
                  { key: "reason", label: "Why not reachable",
                    render: (finding) => el("span", { class: "chain-detail",
                      text: shorten(finding.impactStatement || finding.justification || "—", 70),
                      title: finding.impactStatement || finding.justification || "" }) },
                  { key: "action", label: "", class: "cell-actions",
                    render: (finding) => button("Evidence", { variant: "quiet",
                      onClick: (event) => { event.stopPropagation(); ctx.actions.openFinding(finding.key); } }) },
                ],
                rows: unreachable.slice(0, 6),
                empty: el("div", { style: { padding: "var(--sp-4)" } },
                  callout("warn", "Nothing was dismissed",
                    "Every advisory in this scan was actionable. There is no noise-reduction "
                    + "record to show.")),
              })
            : el("div", { style: { padding: "var(--sp-4)" } },
                callout("warn", "Nothing was dismissed",
                  "This scan produced no unreachable advisories, so there is nothing to list.")),
        })),
      el("div", {},
        riskSummary(analysis),
        pipelinePanel(analysis),
        provenancePanel(ctx))));
}

/* Dependencies — the dependency explorer.
 *
 * Rows come from the inventory the engine actually analysed (report.json
 * packages), joined with SBOM component metadata and the registry inspection
 * the scan recorded. Relationships are rendered only when the SBOM really
 * contains them: an SBOM without a dependency list shows "no graph in SBOM",
 * never a picture of an invented tree.
 */

import { el, frag, shorten } from "../dom.js";
import {
  badge, button, callout, dataTable, mono, notAvailable, panel, severityBadge, stateBlock,
  toolbar, trustBadge,
} from "../components.js";
import { filterPackages, reachabilityStateOf, sortPackages } from "../model.js";
import { days, num } from "../format.js";
import { analysisGate, countLabel, pageHead, usePaged, useSort } from "./common.js";

const FINDINGS_OPTIONS = [
  ["", "All packages"],
  ["actionable", "Has actionable findings"],
  ["any", "Has any advisory"],
  ["none", "No advisories"],
];

const TRUST_OPTIONS = [
  ["", "Any trust state"],
  ["suspicious", "Flagged suspicious"],
  ["registry-unavailable", "Registry lookup failed"],
  ["no-integrity", "No SBOM digest recorded"],
];

const REACH_WORDS = {
  "calls-found": { word: "CALLS FOUND", tone: "bad", glyph: "✓" },
  "no-calls": { word: "NO CALLS FOUND", tone: "ok", glyph: "×" },
  "not-imported": { word: "NOT IMPORTED", tone: "ok", glyph: "×" },
  unknown: { word: "NO FUNCTION DATA", tone: "unknown", glyph: "?" },
};

/**
 * Rollup over the package's findings. A package with no advisory gets an
 * explicit "no advisory" note instead of a reachability verdict.
 */
function reachabilityRollup(pkg) {
  if (!pkg.findings.length) {
    return el("span", { class: "field-hint", text: "no advisory" });
  }
  const counts = new Map();
  for (const finding of pkg.findings) {
    const state = reachabilityStateOf(finding);
    counts.set(state, (counts.get(state) || 0) + 1);
  }
  const order = ["calls-found", "unknown", "no-calls", "not-imported"];
  const first = order.find((state) => counts.get(state));
  const meta = REACH_WORDS[first] || REACH_WORDS.unknown;
  const detail = order.filter((state) => counts.get(state))
    .map((state) => `${counts.get(state)} × ${REACH_WORDS[state].word.toLowerCase()}`).join(" · ");
  return badge(counts.size > 1 ? `${meta.word} (mixed)` : meta.word, meta.tone,
    { glyph: meta.glyph, title: detail });
}

function graphCell(pkg) {
  if (!pkg.edges?.available) {
    return el("span", { class: "field-hint", title: pkg.edges
      ? "the SBOM this scan produced carries no dependency list for this component"
      : "no SBOM dependency data was loaded",
      text: "no graph in SBOM" });
  }
  const out = pkg.edges.dependsOn.length;
  const incoming = pkg.edges.dependedOnBy.length;
  if (!out && !incoming) {
    return el("span", { class: "field-hint", title: "the component appears in the SBOM graph with no edges",
                        text: "isolated node" });
  }
  return el("span", { class: "cell-mono", title: [...pkg.edges.dependsOn, ...pkg.edges.dependedOnBy]
    .map((ref) => String(ref)).join("\n") || "", text: `${num(out)} out · ${num(incoming)} in` });
}

function filterBar(ctx, { filters, ecosystems }) {
  const setFilters = (patch) => ctx.setUi({ filters: { ...filters, ...patch } , page: 1 });
  return toolbar(
    ctx.searchControl(),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Ecosystem" }),
      el("select", { value: filters.ecosystem || "", "aria-label": "Ecosystem filter",
                     onchange: (event) => setFilters({ ecosystem: event.target.value }) },
        [["", "All ecosystems"], ...ecosystems.map((name) => [name, name])].map(([value, label]) =>
          el("option", { value, selected: value === (filters.ecosystem || "") ? true : null, text: label })))),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Advisories" }),
      el("select", { value: filters.findings || "", "aria-label": "Advisory filter",
                     onchange: (event) => setFilters({ findings: event.target.value }) },
        FINDINGS_OPTIONS.map(([value, label]) => el("option", {
          value, selected: value === (filters.findings || "") ? true : null, text: label })))),
    el("label", { class: "field" },
      el("span", { class: "field-hint", text: "Trust" }),
      el("select", { value: filters.trust || "", "aria-label": "Trust filter",
                     onchange: (event) => setFilters({ trust: event.target.value }) },
        TRUST_OPTIONS.map(([value, label]) => el("option", {
          value, selected: value === (filters.trust || "") ? true : null, text: label })))),
    (filters.ecosystem || filters.findings || filters.trust || ctx.ui.query)
      ? button("Clear filters", { variant: "quiet",
          onClick: () => ctx.setUi({ filters: {}, query: "", page: 1 }) })
      : null);
}

export function render(ctx) {
  const gate = analysisGate(ctx);
  const { analysis } = ctx;
  const head = pageHead({
    title: "Dependencies",
    sub: "The inventory this scan analysed, joined with SBOM integrity metadata and registry facts",
    actions: analysis ? [
      button("Findings", { onClick: () => ctx.actions.navigate("vulnerabilities"), variant: "quiet" }),
    ] : [],
  });
  if (gate) return frag(head, el("div", { style: { marginTop: "var(--sp-4)" } }, gate));

  const filters = ctx.ui.filters || {};
  const rows = filterPackages(analysis.packages, {
    query: ctx.ui.query || "",
    ecosystem: filters.ecosystem || "",
    findings: filters.findings || "",
    trust: filters.trust || "",
  });
  const { sort, onSort } = useSort(ctx.ui, ctx.setUi, { key: "findings", dir: "desc" });
  const sorted = sortPackages(rows, sort);
  const paged = usePaged(sorted, ctx.ui, ctx.setUi, 25);
  const ecosystems = [...analysis.ecosystemCounts.keys()].sort();

  const columns = [
    { key: "name", label: "Package", sortable: true,
      render: (pkg) => el("div", {},
        el("div", { class: "pkg", text: pkg.name }),
        pkg.purl ? el("div", { class: "field-hint", text: shorten(pkg.purl, 46), title: pkg.purl }) : null) },
    { key: "version", label: "Version", sortable: true, class: "cell-mono",
      render: (pkg) => pkg.version },
    { key: "ecosystem", label: "Ecosystem", sortable: true, render: (pkg) => pkg.ecosystem },
    { key: "findings", label: "Findings", sortable: true,
      render: (pkg) => pkg.findingCount
        ? el("span", {}, `${num(pkg.findingCount)} `,
            el("span", { class: "field-hint",
                         text: `(${num(pkg.actionableCount)} actionable, ${num(pkg.unreachableCount)} unreachable)` }))
        : el("span", { class: "field-hint", text: "none returned" }) },
    { key: "reach", label: "Reachability",
      render: (pkg) => reachabilityRollup(pkg) },
    { key: "trust", label: "Trust", render: (pkg) => trustBadge(pkg) },
    { key: "severity", label: "Risk", sortable: true,
      render: (pkg) => pkg.worstSeverity ? severityBadge(pkg.worstSeverity)
        : el("span", { class: "field-hint", text: "no advisory" }) },
    { key: "graph", label: "Graph", render: (pkg) => graphCell(pkg) },
    { key: "registry", label: "Registry", render: (pkg) => pkg.registry
        ? el("span", { class: "field-hint", title: pkg.registry.reasons.join("; "),
                       text: `${pkg.registry.status || "unknown"} · ${days(pkg.registry.ageDays)}` })
        : el("span", { class: "field-hint", text: "not inspected" }) },
    { key: "action", label: "", class: "cell-actions",
      render: (pkg) => button("Findings", { variant: "quiet", disabled: !pkg.findingCount,
        title: pkg.findingCount ? `Open the ${pkg.findingCount} finding(s) for ${pkg.name}`
          : "this package has no advisory in this scan",
        onClick: (event) => { event.stopPropagation(); ctx.actions.openPackageFindings(pkg); } }) },
  ];

  return frag(
    head,
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Inventory",
        note: countLabel(paged.total, analysis.packages.length, "dependencies"),
        flush: true,
        body: frag(
          filterBar(ctx, { filters, ecosystems }),
          dataTable({
            columns,
            rows: paged.rows,
            sort, onSort,
            onRowClick: (pkg) => {
              if (pkg.findingCount) ctx.actions.openPackageFindings(pkg);
            },
            empty: el("div", { style: { padding: "var(--sp-4)" } },
              stateBlock({ tone: "idle", mark: "∅",
                title: analysis.packages.length ? "No package matches these filters" : "No dependencies analysed",
                body: analysis.packages.length
                  ? "Relax the filters to see the remaining inventory. Filtering changes only what is "
                    + "displayed, never a verdict."
                  : "The scan produced no package inventory, so there is nothing to explore. Check the "
                    + "manifest discovery stage in the Overview view.",
                actions: [button("Clear filters", { onClick: () => ctx.setUi({ filters: {}, query: "" }) })] })),
          }),
          paged.pager),
        foot: [
          el("span", { text: `Direct declarations only: these are the manifests the engine parsed `
            + `(${num(ecosystems.length)} ecosystem${ecosystems.length === 1 ? "" : "s"}). Transitive `
            + "resolution is not performed by this engine, so no transitive row is invented here." }),
        ],
      })),

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Unresolved dependency declarations",
        note: analysis.unresolved.length
          ? `${num(analysis.unresolved.length)} declaration(s) with no single exact version`
          : "none",
        flush: true,
        body: analysis.unresolved.length
          ? [
              el("div", { style: { padding: "var(--sp-4)" } },
                callout("warn", "No advisory lookup was possible for these entries",
                  "A ranged, wildcard, placeholder or unparseable version cannot be matched to a concrete "
                  + "release, so nothing was queried for it. The engine discloses the entry instead of "
                  + "dropping it, which is why the inventory can never look cleaner than it is.")),
              dataTable({
                columns: [
                  { key: "name", label: "Dependency", render: (row) => mono(row.name) },
                  { key: "spec", label: "Version specifier",
                    render: (row) => el("span", { class: "cell-mono",
                      text: row.version_specifier || "*" }) },
                  { key: "file", label: "Manifest", render: (row) => el("span", { class: "chain-detail",
                    text: shorten(row.file || "unknown", 60), title: row.file || "" }) },
                  { key: "reason", label: "Reason",
                    render: (row) => row.reason ? badge(String(row.reason).toUpperCase(), "warn",
                      { plain: true }) : notAvailable("not reported") },
                ],
                rows: analysis.unresolved,
              }),
            ]
          : el("div", { style: { padding: "var(--sp-4)" } },
              stateBlock({ tone: "ok", mark: "✓", title: "No unresolved declarations",
                body: "Every manifest entry in this scan resolved to exactly one version, so the whole "
                  + "declared inventory could be advisory-checked." })),
      })),

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "SBOM inventory only",
        note: analysis.sbomOnly.length
          ? `${num(analysis.sbomOnly.length)} component(s) not in the analysed inventory`
          : "none",
        flush: true,
        body: analysis.sbomOnly.length
          ? [
              el("div", { style: { padding: "var(--sp-4)" } },
                callout("info", "Inventory only — not advisory-analysed in this scan",
                  "These components appear in sbom.cdx.json but not in the inventory the engine queried. "
                  + "They are listed so nothing is hidden, but no verdict exists for them: absence of a "
                  + "finding here means no lookup happened, not that the component is clean.")),
              dataTable({
                columns: [
                  { key: "name", label: "Component", render: (row) => el("span", { class: "pkg",
                    text: row.name }) },
                  { key: "version", label: "Version", class: "cell-mono", render: (row) => row.version },
                  { key: "purl", label: "purl", render: (row) => row.purl
                      ? mono(shorten(row.purl, 44)) : notAvailable("no purl recorded") },
                  { key: "licenses", label: "Licenses", render: (row) => row.licenses.length
                      ? row.licenses.join(", ") : notAvailable("none declared") },
                  { key: "digests", label: "Digests", align: "right", render: (row) => row.hashes
                      ? `${num(row.hashes)} recorded` : notAvailable("none recorded") },
                ],
                rows: analysis.sbomOnly,
              }),
            ]
          : el("div", { style: { padding: "var(--sp-4)" } },
              stateBlock({ tone: "ok", mark: "✓", title: "The SBOM and the analysed inventory agree",
                body: "Every component in sbom.cdx.json corresponds to a package the engine analysed, so "
                  + "there is no unanalysed inventory to disclose." })),
        foot: [
          el("span", { text: "Components are matched by purl, falling back to name+version; the match kind "
            + "is shown per package on the Trust view." }),
        ],
      })));
}

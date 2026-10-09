/* Trust — the integrity and provenance signals ChainGuard actually produces.
 *
 * There is no trust score in this product and this view does not invent one.
 * Every cell is either a value recorded by the engine's registry inspection or
 * SBOM component, or an explicit "Not available". Signals the engine does not
 * produce yet are listed as planned capabilities, never estimated.
 */

import { el, frag, shorten } from "../dom.js";
import {
  button, callout, dataTable, dot, kvList, notAvailable, panel, planGrid,
  registrySummary, stateBlock, toolbar, toolbarCount, trustBadge, trustFacts, trustSignalRow,
} from "../components.js";
import { filterPackages, sortPackages } from "../model.js";
import { days, num } from "../format.js";
import { analysisGate, metricStrip, pageHead, usePaged, useSort } from "./common.js";

const SIGNALS = [
  ["Registry existence and status", "the package version was looked up in its canonical registry"],
  ["Lookup failures", "an unavailable lookup is reported as unknown, never as safe"],
  ["Package age and publish date", "age of the inspected release, from the registry response"],
  ["Release count", "how many releases the registry has for this package"],
  ["Typosquat proximity hints", "registry names within a small edit distance, as the engine reports them"],
  ["Integrity digests", "hashes recorded in the SBOM component — recorded, not verified"],
  ["Declared licenses", "licenses declared in the SBOM component"],
  ["Distribution references", "external reference URLs recorded in the SBOM component"],
  ["Dependency-graph edges", "dependsOn / dependedOnBy edges present in the SBOM dependency list"],
];

const MISSING = [
  "Package signatures and attestations (Sigstore-style verification)",
  "SLSA provenance levels",
  "Maintainer and ownership history",
  "Release-health trends over time",
  "Package reputation scoring",
  "Behavioural or malware analysis",
];

function registryCell(pkg) {
  const registry = pkg.registry;
  const tone = registry?.suspicious || registry?.exists === false ? "bad"
    : registry?.lookupError ? "warn" : registry ? "ok" : "idle";
  const word = registry
    ? (registry.suspicious ? "flagged"
      : registry.exists === false ? "absent"
        : registry.lookupError ? "lookup failed"
          : registry.exists ? "present" : "unknown")
    : "not inspected";
  return el("span", { class: "field-inline" },
    dot(tone),
    el("span", { class: "chain-detail", text: word }));
}

function integrityCell(pkg) {
  const hashes = pkg.sbom?.hashes || [];
  if (!hashes.length) return notAvailable("none recorded");
  const algorithms = [...new Set(hashes.map((hash) => hash.alg))].join(", ");
  return el("div", {},
    el("div", { class: "cell-mono", text: `${hashes.length} × ${algorithms}` }),
    el("div", { class: "field-hint", text: "recorded, not verified" }));
}

function graphCell(pkg) {
  if (!pkg.edges?.available) return notAvailable("no graph");
  return el("span", { class: "cell-mono",
    text: `${pkg.edges.dependsOn.length} out · ${pkg.edges.dependedOnBy.length} in` });
}

function summaryStrip(packages) {
  const suspicious = packages.filter((pkg) => pkg.registry?.suspicious).length;
  const failed = packages.filter((pkg) => pkg.registry?.lookupError).length;
  const withDigest = packages.filter((pkg) => (pkg.sbom?.hashes?.length || 0) > 0).length;
  const noComponent = packages.filter((pkg) => !pkg.sbomMatch).length;
  return metricStrip([
    { value: num(packages.length), label: "Packages inspected", tone: "info",
      note: "registry + SBOM signals" },
    { value: num(suspicious), label: "Flagged suspicious", tone: suspicious ? "bad" : "idle",
      note: "engine registry checks" },
    { value: num(failed), label: "Lookups failed", tone: failed ? "warn" : "idle",
      note: "reported as unknown, not safe" },
    { value: num(withDigest), label: "With an integrity digest", tone: withDigest ? "ok" : "idle",
      note: "recorded in the SBOM" },
    { value: num(noComponent), label: "No SBOM component", tone: noComponent ? "warn" : "idle",
      note: "joined by purl or name+version" },
  ]);
}

function signalInventory() {
  return panel({
    title: "Signals available today",
    note: "what this engine version actually records",
    body: [
      el("div", { class: "split" },
        el("div", {}, SIGNALS.map(([label, note]) => trustSignalRow(label, "recorded", "ok", note))),
        el("div", {},
          el("h3", { class: "panel-title", text: "Not produced yet" }),
          el("ul", { class: "evidence-list", style: { marginTop: "var(--sp-2)" } },
            MISSING.map((item) => el("li", { class: "evidence-item" },
              el("span", { class: "loc", text: "—" }),
              el("span", { text: item }),
              el("span", { class: "kind", text: "planned" })))),
          el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
            text: "No trust score, ratio or verdict is computed anywhere in this dashboard. "
              + "The signals above are evidence a human or a policy engine can weigh." }))),
    ],
  });
}

export function render(ctx) {
  const gate = analysisGate(ctx);
  const { analysis, state } = ctx;
  const head = pageHead({
    title: "Trust",
    sub: "Integrity, registry and provenance signals as recorded by the scan engine",
    actions: analysis ? [
      button("Dependencies", { onClick: () => ctx.actions.navigate("dependencies"), variant: "quiet" }),
      button("Artifacts", { onClick: () => ctx.actions.navigate("reports"), variant: "quiet" }),
    ] : [],
  });
  if (gate) return frag(head, el("div", { style: { marginTop: "var(--sp-4)" } }, gate));

  const packages = analysis.packages;
  const filters = ctx.ui.filters || {};
  const query = ctx.ui.query || "";
  const ecosystem = filters.ecosystem || "";
  const trust = filters.trust || "";
  const openKey = ctx.ui.open || null;

  const ecosystems = [...analysis.ecosystemCounts.keys()].sort();
  const filtered = filterPackages(packages, {
    query, ecosystem,
    trust: ["suspicious", "registry-unavailable", "no-integrity"].includes(trust) ? trust : "",
  }).filter((pkg) => (trust === "no-sbom" ? !pkg.sbomMatch : true));

  const { sort, onSort } = useSort(ctx.ui, ctx.setUi, { key: "trust", dir: "asc" });
  const sorted = sortPackages(filtered, sort);
  const paged = usePaged(sorted, ctx.ui, ctx.setUi, 25);
  const selected = packages.find((pkg) => pkg.key === openKey) || null;

  const openPackage = (pkg) => ctx.setUi({ open: pkg.key === openKey ? null : pkg.key });

  const columns = [
    { key: "name", label: "Package", sortable: true,
      render: (pkg) => el("div", {},
        el("div", { class: "pkg", text: pkg.name }),
        el("div", { class: "field-hint", text: pkg.purl ? shorten(pkg.purl, 46) : pkg.ecosystem })) },
    { key: "version", label: "Version", sortable: true, class: "cell-mono",
      render: (pkg) => pkg.version },
    { key: "registry", label: "Registry", render: (pkg) => frag(trustBadge(pkg), registryCell(pkg)) },
    { key: "age", label: "Age", sortable: true, class: "cell-mono",
      render: (pkg) => pkg.registry?.ageDays === null || pkg.registry?.ageDays === undefined
        ? notAvailable("—") : days(pkg.registry.ageDays) },
    { key: "releases", label: "Releases", sortable: true, align: "right", class: "cell-mono",
      render: (pkg) => pkg.registry?.releaseCount === null || pkg.registry?.releaseCount === undefined
        ? notAvailable("—") : num(pkg.registry.releaseCount) },
    { key: "integrity", label: "Integrity", render: (pkg) => integrityCell(pkg) },
    { key: "licenses", label: "Licenses",
      render: (pkg) => pkg.sbom?.licenses?.length
        ? el("span", { class: "chain-detail", text: pkg.sbom.licenses.join(", ") })
        : notAvailable("none declared") },
    { key: "graph", label: "Graph", render: (pkg) => graphCell(pkg) },
    { key: "action", label: "", class: "cell-actions",
      render: (pkg) => button(pkg.key === openKey ? "Hide" : "Inspect", { variant: "quiet",
        onClick: (event) => { event.stopPropagation(); openPackage(pkg); } }) },
  ];

  return frag(
    head,

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({ title: "Trust signal inventory", note: "no score, no inference — recorded facts only",
              body: summaryStrip(packages) })),

    el("div", { style: { marginTop: "var(--sp-4)" } }, signalInventory()),

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Packages",
        note: `${num(paged.total)} of ${num(packages.length)} packages`,
        flush: true,
        body: frag(
          toolbar(
            ctx.searchControl(),
            el("label", { class: "field" },
              el("span", { class: "field-hint", text: "Ecosystem" }),
              el("select", { value: ecosystem, "aria-label": "Ecosystem filter",
                             onchange: (event) => ctx.setUi({ filters: { ...filters, ecosystem: event.target.value }, page: 1 }) },
                [["", "All ecosystems"], ...ecosystems.map((name) => [name, name])].map(([value, label]) =>
                  el("option", { value, selected: value === ecosystem ? true : null, text: label })))),
            el("label", { class: "field" },
              el("span", { class: "field-hint", text: "Signal" }),
              el("select", { value: trust, "aria-label": "Trust signal filter",
                             onchange: (event) => ctx.setUi({ filters: { ...filters, trust: event.target.value }, page: 1 }) },
                [["", "Everything"],
                 ["suspicious", "Flagged suspicious"],
                 ["registry-unavailable", "Registry lookup failed"],
                 ["no-integrity", "No integrity digest"],
                 ["no-sbom", "No SBOM component match"]].map(([value, label]) =>
                  el("option", { value, selected: value === trust ? true : null, text: label })))),
            query || ecosystem || trust
              ? button("Clear filters", { variant: "quiet",
                  onClick: () => ctx.setUi({ filters: {}, query: "", page: 1 }) })
              : null,
            toolbarCount(`${num(sorted.length)} shown`)),
          dataTable({
            columns,
            rows: paged.rows,
            sort, onSort,
            onRowClick: (pkg) => openPackage(pkg),
            rowClass: (pkg) => (pkg.registry?.suspicious ? "row-sev-critical" : null),
            rowAttrs: (pkg) => ({ "aria-selected": pkg.key === openKey ? "true" : "false" }),
            empty: el("div", { style: { padding: "var(--sp-4)" } },
              stateBlock({ tone: "idle", mark: "∅",
                title: packages.length ? "No package matches these filters" : "No trust information available",
                body: packages.length
                  ? "Relax the filters to see the rest of the inventory. Filtering never changes a verdict."
                  : "This scan produced no package inventory, so there is nothing to report on. "
                    + "An empty trust view is not a statement about the code that was scanned.",
                actions: [button("Reset filters", { onClick: () => ctx.setUi({ filters: {}, query: "" }) })] })),
          }),
          paged.pager),
        foot: [el("span", { text: "Joined to the SBOM by purl, then by name+version; the match kind is shown "
          + "per package so a weak join is never presented as a strong one." })],
      })),

    selected
      ? el("div", { style: { marginTop: "var(--sp-4)" } },
          panel({
            title: `${selected.name}@${selected.version}`,
            note: "full trust record for this package",
            actions: [button("Close", { onClick: () => ctx.setUi({ open: null }), variant: "quiet" })],
            body: [
              el("div", { class: "split" },
                el("div", {},
                  el("div", { class: "section-title", text: "Recorded signals" }),
                  kvList(trustFacts(selected).map(([label, value, note]) => [label, value,
                    { mono: true, missing: note || "Not available" }]))),
                el("div", {},
                  el("div", { class: "section-title", text: "Registry inspection" }),
                  registrySummary(selected.registry),
                  selected.sbom
                    ? frag(
                        el("div", { class: "section-title", text: "SBOM component" }),
                        kvList([
                          ["Reference", selected.sbom.bomRef, { mono: true, breakAll: true }],
                          ["Component type", selected.sbom.type],
                          ["Digests", selected.sbom.hashes.length
                            ? selected.sbom.hashes.map((hash) => `${hash.alg}:${shorten(hash.content, 16)}…`).join(" ")
                            : null, { mono: true }],
                          ["External references", selected.sbom.references.length
                            ? selected.sbom.references.map((ref) => `${ref.type}: ${ref.url}`).join(" | ")
                            : null, { mono: true, breakAll: true }],
                        ]))
                    : el("div", { class: "section-title", text: "SBOM component" }),
                  selected.sbom ? null : notAvailable("no SBOM component matched this package"),
                )),
            ],
          }))
      : null,

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Planned trust signals",
        note: "not produced by this engine version",
        body: [planGrid([
          { name: "Signatures and attestations",
            body: "Would need Sigstore-style verification metadata per artifact; the engine records hashes "
              + "only, so nothing here can be verified today.", state: "PLANNED" },
          { name: "SLSA provenance levels",
            body: "Would need the build system's provenance attestation, which is not part of the scanned "
              + "manifests or registry responses.", state: "PLANNED" },
          { name: "Maintainer and ownership signals",
            body: "Would need registry maintainer history and ownership change events; no such lookup exists "
              + "in this engine.", state: "PLANNED" },
          { name: "Release-health trends",
            body: "Would need release history over time and a stored scan history; the API keeps no scan "
              + "index.", state: "PLANNED" },
          { name: "Package reputation scoring",
            body: "Would need a reputation source. A score computed here would be an opinion, not evidence.",
            state: "COMING SOON" },
          { name: "Behavioural / malware analysis",
            body: "Would need install-hook and payload analysis of package contents, which this phase does "
              + "not perform.", state: "PLANNED" },
        ])],
      })),

    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "What these signals do and do not prove",
        body: [
          callout("warn", "Recorded is not verified",
            "An SBOM digest proves the inventory recorded a hash for a component; it does not prove the "
            + "artifact was checked against a trusted signature, and this engine performs no signature "
            + "verification. Likewise a successful registry lookup proves the package exists, not that it "
            + "is safe."),
          el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
            text: "The engine's own limitations apply here: registry checks are heuristics based on a small "
              + "popularity list, and an unavailable registry lookup is reported as unknown rather than "
              + "suspicious. Review results before making security decisions." }),
          state.health?.status === "degraded"
            ? callout("danger", "API reported a degraded engine",
                state.health.engine?.detail || "the engine health check failed, so trust signals may be incomplete.")
            : null,
        ],
      })));
}

/* Reports — the four artifacts the engine writes, as the API serves them.
 *
 * Nothing on this page is synthesised: a row exists because the scan produced
 * that file, and buttons only appear for files that were actually fetched. The
 * API serves exactly four artifact names (report.json, trace.json,
 * sbom.cdx.json, openvex.json) and deliberately not the stdout/stderr logs, so
 * the console output panel is limited to what the scan response returned.
 */

import { el, frag, shorten } from "../dom.js";
import { artifactUrl } from "../api.js";
import {
  badge, button, callout, kvList, notAvailable, panel, sectionTitle, stateBlock,
} from "../components.js";
import { durationMs, fmtDateTime, num } from "../format.js";
import { emptyState, pageHead } from "./common.js";

/* Key -> file name -> what the file is for. The key matches analysis.artifacts /
 * analysis.artifactsLoaded / analysis.artifactErrors and the API's own names. */
const ARTIFACT_DEFS = [
  { key: "report", purpose: "Deterministic verdicts, reachability evidence and the engine's summary" },
  { key: "trace", purpose: "Per-stage timings, evidence chains and per-package journeys" },
  { key: "sbom", purpose: "CycloneDX inventory with digests, licences and SBOM graph edges" },
  { key: "vex", purpose: "Machine-readable OpenVEX statements for every decided advisory" },
];

const CAPTURE_LIMIT = 20000;

function artifactName(ctx, key) {
  return ctx.analysis?.artifactNames?.[key] || { report: "report.json", trace: "trace.json",
    sbom: "sbom.cdx.json", vex: "openvex.json" }[key] || key;
}

function loaded(ctx, key) {
  return Boolean(ctx.analysis?.artifactsLoaded?.[key]);
}

function errorFor(ctx, key) {
  return ctx.analysis?.artifactErrors?.[key] || null;
}

/** One real artifact row: available files get View/Download, missing ones say why. */
function artifactRow(ctx, key) {
  const name = artifactName(ctx, key);
  const path = ctx.analysis?.artifacts?.[key] || null;
  const available = loaded(ctx, key);
  const error = errorFor(ctx, key);

  const actions = available
    ? el("div", { class: "artifact-actions" },
        button(ctx.ui.preview === key ? "Hide" : "Inspect", {
          variant: "quiet",
          onClick: () => ctx.setUi({ preview: ctx.ui.preview === key ? null : key }),
        }),
        button("View", { variant: "quiet", onClick: () => ctx.actions.viewArtifact(key) }),
        button("Download", { variant: "quiet", onClick: () => ctx.actions.downloadArtifact(key) }))
    : null;

  return el("div", { class: "artifact-row" },
    el("div", {},
      el("div", { class: "artifact-name", text: name }),
      el("div", { class: "artifact-meta", title: path || "",
                  text: path ? shorten(path, 96) : "on-disk path not reported by the API" }),
      el("div", { class: "field-hint", text: ARTIFACT_DEFS.find((def) => def.key === key)?.purpose || "" }),
      !available && error
        ? el("div", { class: "field-hint",
                      text: `${error.code}: ${error.message}` })
        : null),
    el("div", { class: "field-inline", style: { marginLeft: "auto" } },
      available
        ? badge("available", "ok", { glyph: "✓" })
        : badge(error?.code || "missing", error ? (error.code === "ARTIFACT_MISSING" ? "warn" : "high") : "unknown",
                { glyph: "!" }),
      actions));
}

/** Verbatim values the dashboard retained from each file (never re-derived). */
function summaryFor(ctx, key) {
  const analysis = ctx.analysis;
  if (key === "report") {
    const unresolved = analysis.unresolved.length;
    return [
      kvList([
        ["Findings", num(analysis.findings.length)],
        ["Actionable", num(analysis.findings.filter((finding) => finding.actionable).length)],
        ["Packages in inventory", num(analysis.packages.length)],
        ["Target", analysis.target, { mono: true, breakAll: true }],
        ["Diff ref", analysis.options?.diff_ref ?? null],
        ["Unresolved declarations", unresolved
          ? `${num(unresolved)} — declared without an exact version, so no advisory lookup was possible`
          : "none"],
      ]),
      el("div", { class: "section-title", text: "summary object, as written by the engine" }),
      analysis.summary
        ? el("pre", { class: "code-block", text: JSON.stringify(analysis.summary, null, 2) })
        : notAvailable("the summary object was not part of the scan response"),
    ];
  }
  if (key === "trace") {
    const metadata = analysis.runMetadata || {};
    const flags = metadata.flags || {};
    return [kvList([
      ["Stages", num(analysis.stages.length)],
      ["Evidence chains", num(analysis.chains.length)],
      ["Package journeys", num(analysis.journeys.length)],
      ["Totals", analysis.totals ? JSON.stringify(analysis.totals) : null],
      ["Tool version", metadata.tool_version || null],
      ["Python version", metadata.python_version || null],
      ["Run timestamp", metadata.timestamp ? fmtDateTime(metadata.timestamp) : null],
      ["Project path", metadata.project_path || null, { mono: true, breakAll: true }],
      ["Flags", Object.keys(flags).length
        ? Object.entries(flags).map(([flag, value]) => `${flag}=${value}`).join("  ") : null],
    ])];
  }
  if (key === "sbom") {
    const spec = analysis.sbomSpec || {};
    const tools = analysis.sbomMetadata?.tools?.components || [];
    const matched = analysis.packages.filter((pkg) => pkg.sbom).length;
    return [kvList([
      ["BOM format", spec.bomFormat || null],
      ["Spec version", spec.specVersion || null],
      ["Serial number", spec.serialNumber || null, { mono: true, breakAll: true }],
      ["Tool", tools.length
        ? tools.map((tool) => `${tool.name}@${tool.version || "?"}`).join(", ") : null],
      ["Components matched to the inventory", `${num(matched)} of ${num(analysis.packages.length)}`],
      ["Additional SBOM components", analysis.sbomOnly.length
        ? `${num(analysis.sbomOnly.length)} — present in the SBOM but not in the analysed inventory`
        : "none"],
      ["Services", spec.services === undefined ? null : num(spec.services)],
      ["SBOM timestamp", analysis.sbomMetadata?.timestamp
        ? fmtDateTime(analysis.sbomMetadata.timestamp) : null],
    ])];
  }
  return [kvList([
    ["Statements matched to findings", `${num(analysis.findings.filter((finding) => finding.vex).length)} `
      + `of ${num(analysis.findings.length)}`],
    ["Findings without a statement", num(analysis.findings.filter((finding) => !finding.vex).length)],
    ["Author", analysis.raw?.vex?.author || null,
      { missing: "the document did not report an author" }],
    ["Document timestamp", analysis.raw?.vex?.timestamp
      ? fmtDateTime(analysis.raw.vex.timestamp) : null,
      { missing: "the document carried no timestamp" }],
    ["Statements in the file", analysis.raw?.vex?.statements
      ? num(analysis.raw.vex.statements.length) : null],
  ]), callout("info", "Where to read the rest",
    "Statement bodies are shown per finding in the investigation view, and the complete file "
    + "(including the document-level @context, @id, author and timestamp) is one click away with View.")];
}

/**
 * Content for the inspect panel.
 *
 * The whole parsed artifact is retained on the analysis object (model.js keeps
 * `raw`), so this prints the file the API served — not a reconstruction.
 * Only when an artifact was not loaded does it fall back to the sub-objects the
 * dashboard kept, and it says so in that case.
 */
function captureFor(ctx, key) {
  const analysis = ctx.analysis;
  const raw = analysis.raw?.[key];
  if (raw) {
    return { note: "the complete parsed artifact as served by the API", value: raw };
  }
  if (key === "report") {
    return {
      note: "report.json was not loaded; showing the finding records this scan returned",
      value: analysis.findings.map((finding) => finding.raw),
    };
  }
  if (key === "trace") {
    return {
      note: "trace.json was not loaded; showing the sub-objects the scan response carried",
      value: { run_metadata: analysis.runMetadata, stages: analysis.stages,
               evidence_chains: analysis.chains, journeys: analysis.journeys,
               totals: analysis.totals },
    };
  }
  if (key === "sbom") {
    return {
      note: "sbom.cdx.json was not loaded; showing the spec fields and metadata",
      value: { bomFormat: analysis.sbomSpec?.bomFormat, specVersion: analysis.sbomSpec?.specVersion,
               serialNumber: analysis.sbomSpec?.serialNumber, metadata: analysis.sbomMetadata },
    };
  }
  return {
    note: "openvex.json was not loaded; showing the statements returned per finding",
    value: analysis.findings.filter((finding) => finding.vex).map((finding) => finding.vex),
  };
}

function inspectPanel(ctx, key) {
  const { note, value } = captureFor(ctx, key);
  const text = JSON.stringify(value ?? null, null, 2);
  const truncated = text.length > CAPTURE_LIMIT;
  const name = artifactName(ctx, key);
  return el("div", { style: { marginTop: "var(--sp-3)" } },
    el("div", { class: "field-hint", text: `${note}. JSON.stringify() below is display formatting only; "
      + "the API serves the file byte-for-byte and the dashboard never rewrites it.` }),
    truncated
      ? el("div", { style: { marginTop: "var(--sp-2)" } },
          callout("warn", "Preview truncated",
            `Showing the first ${num(CAPTURE_LIMIT)} of ${num(text.length)} characters. `
            + `Open ${name} with View to read the whole file.`))
      : null,
    el("pre", { class: "code-block", style: { marginTop: "var(--sp-2)" },
                text: truncated ? text.slice(0, CAPTURE_LIMIT) : text }),
    el("div", { class: "field-inline", style: { marginTop: "var(--sp-2)" } },
      button(`View ${name} as served`, { variant: "quiet", onClick: () => ctx.actions.viewArtifact(key) }),
      button("Download", { variant: "quiet", onClick: () => ctx.actions.downloadArtifact(key) })));
}

function consolePanel(ctx) {
  const scan = ctx.analysis.scan;
  if (!scan) {
    return panel({ title: "Engine console output",
                   body: [notAvailable("the scan response carried no engine run metadata")] });
  }
  const stdout = String(scan.stdout || "");
  const stderr = String(scan.stderr || "");
  const logs = ctx.analysis.artifacts || {};
  return panel({
    title: "Engine console output",
    note: `exit code ${String(scan.exit_code)} · ${durationMs(scan.duration_ms)}`,
    body: [
      el("div", { class: "field-hint", text: "Captured by the API and truncated at its configured limit. "
        + "The full text is written next to the artifacts as stdout.log and stderr.log — the artifact "
        + "endpoint serves only the four JSON artifacts, so those logs are intentionally not exposed here." }),
      el("div", { class: "section-title", text: "stdout" }),
      stdout ? el("pre", { class: "code-block", text: stdout })
        : notAvailable("the engine wrote nothing to stdout"),
      el("div", { class: "section-title", text: "stderr" }),
      stderr ? el("pre", { class: "code-block", text: stderr })
        : notAvailable("the engine wrote nothing to stderr"),
      kvList([
        ["stdout.log on disk", logs.stdout_log || null, { mono: true, breakAll: true }],
        ["stderr.log on disk", logs.stderr_log || null, { mono: true, breakAll: true }],
      ]),
    ],
  });
}

function urlFooter(ctx) {
  const scanId = ctx.analysis.scanId;
  const repositoryId = ctx.analysis.repositoryId;
  if (!scanId || !repositoryId) {
    return [el("span", { text: "Artifact URLs need a scan id and repository id; this scan response "
      + "did not provide both." })];
  }
  return [
    el("span", { text: "Artifact endpoints (read-only):" }),
    el("pre", { class: "code-block", style: { flex: "1 1 100%" },
                text: ARTIFACT_DEFS.map((def) =>
                  artifactUrl(scanId, repositoryId, artifactName(ctx, def.key))).join("\n") }),
    el("span", { text: "The dashboard never modifies an artifact: these are GET requests, and only "
      + "files that exist on disk are served." }),
  ];
}

export function render(ctx) {
  const analysis = ctx.analysis;
  const head = pageHead({
    title: "Reports",
    sub: "The four artifacts the engine writes, served exactly as they are on disk",
    actions: analysis ? [
      button("Overview", { onClick: () => ctx.actions.navigate("overview"), variant: "quiet" }),
    ] : [],
  });

  if (!analysis) {
    return frag(head, el("div", { style: { marginTop: "var(--sp-4)" } },
      emptyState({
        title: "No report artifacts yet",
        body: "Artifacts belong to one scan id: the engine writes them into an isolated output "
          + "directory and the API serves them read-only from there. Run a scan, or reopen an "
          + "earlier scan by its scan id on the Scans page, and its report.json, trace.json, "
          + "sbom.cdx.json and openvex.json appear here.",
        actions: [button("Go to the Scans page", { variant: "primary",
          onClick: () => ctx.actions.navigate("scans") })],
      })));
  }

  const loadedCount = ARTIFACT_DEFS.filter((def) => loaded(ctx, def.key)).length;
  const artifactsPanel = panel({
    title: "Scan artifacts",
    note: `${num(loadedCount)} of ${num(ARTIFACT_DEFS.length)} available for this scan`,
    flush: true,
    body: [
      el("div", {}, ARTIFACT_DEFS.map((def) => frag(
        artifactRow(ctx, def.key),
        loaded(ctx, def.key) && ctx.ui.preview === def.key ? inspectPanel(ctx, def.key) : null))),
      loadedCount < ARTIFACT_DEFS.length
        ? el("div", { style: { padding: "var(--sp-4)" } },
            callout("warn", "Some artifacts are not available",
              "Rows without actions are files this scan did not produce. Nothing here is substituted "
              + "or reconstructed to fill the gap."))
        : null,
    ],
  });

  const detailsPanel = panel({
    title: "Artifact contents",
    note: "read back from the API, summarized from what this scan actually returned",
    body: ARTIFACT_DEFS.map((def) => frag(
      sectionTitle(artifactName(ctx, def.key), loaded(ctx, def.key) ? null : "not loaded"),
      loaded(ctx, def.key)
        ? summaryFor(ctx, def.key)
        : stateBlock({ tone: "idle", mark: "!", title: `${artifactName(ctx, def.key)} not available`,
                       body: errorFor(ctx, def.key)?.message
                         || "This artifact was not part of the scan response." }))),
  });

  return frag(
    head,
    el("div", { style: { marginTop: "var(--sp-4)" } }, artifactsPanel),
    el("div", { style: { marginTop: "var(--sp-4)" } }, detailsPanel),
    el("div", { style: { marginTop: "var(--sp-4)" } }, consolePanel(ctx)),
    panel({ title: "Provenance", body: [kvList([
      ["Scan id", analysis.scanId, { mono: true, breakAll: true }],
      ["Repository id", analysis.repositoryId, { mono: true }],
      ["API status", analysis.status],
      ["Engine state", analysis.state],
      ["Engine version", analysis.runMetadata?.tool_version || null],
    ])] }),
    el("div", { class: "footer-note", style: { display: "flex", flexDirection: "column",
                                               gap: "var(--sp-2)" } }, urlFooter(ctx)));
}

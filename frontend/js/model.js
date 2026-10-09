/* Scan normalization: turn a real API response plus its real artifacts into one
 * analysis object the views read.
 *
 * Rules this module follows strictly:
 *  - counts and verdicts come from the engine (summary / status / justification);
 *    nothing is recomputed as a security decision here;
 *  - a value the engine did not provide stays `null`/absent and the UI prints
 *    "Not available" rather than a guess;
 *  - joins between report, SBOM and registry data are by purl (falling back to
 *    name+version) and the match kind is kept so the UI can say how it joined.
 */

import { severityOf, toneForBand, purlParts, SEVERITY_ORDER, bandForScore } from "./format.js";

export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

export function packageKey(pkg) {
  if (!pkg) return "unknown";
  const purl = String(pkg.purl || "").trim();
  if (purl) return purl;
  return `${pkg.ecosystem || "?"}:${pkg.name || "?"}@${pkg.version || "?"}`;
}

function bareName(name) {
  return String(name || "").split(/[.:/]/).filter(Boolean).pop().toLowerCase();
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function numeric(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

/** Index one SBOM component list by purl, then by name+version, then by name. */
function indexComponents(sbom) {
  const byPurl = new Map();
  const byNameVersion = new Map();
  const byName = new Map();
  for (const component of safeArray(sbom?.components)) {
    const purl = String(component.purl || "");
    if (purl) byPurl.set(purl, component);
    const key = `${bareName(component.name)}@${String(component.version || "").toLowerCase()}`;
    byNameVersion.set(key, component);
    if (!byName.has(bareName(component.name))) byName.set(bareName(component.name), component);
  }
  return { byPurl, byNameVersion, byName };
}

function componentSignals(component) {
  if (!component) return null;
  const hashes = safeArray(component.hashes).filter((hash) => hash && hash.content);
  const licenses = safeArray(component.licenses).map((entry) => {
    const license = entry?.license || {};
    return license.id || license.name || (typeof entry === "string" ? entry : null);
  }).filter(Boolean);
  const references = safeArray(component.externalReferences)
    .map((ref) => ({ type: ref?.type || "other", url: ref?.url || null }))
    .filter((ref) => ref.url);
  return {
    purl: component.purl || null,
    bomRef: component["bom-ref"] || null,
    type: component.type || null,
    group: component.group || "",
    hashes: hashes.map((hash) => ({ alg: hash.alg || "?", content: hash.content })),
    licenses,
    references,
  };
}

function registrySignals(entry) {
  if (!entry) return null;
  return {
    suspicious: Boolean(entry.suspicious),
    status: entry.status || null,
    exists: entry.exists === undefined ? null : Boolean(entry.exists),
    created: entry.created || null,
    ageDays: entry.age_days === undefined ? null : numeric(entry.age_days, null),
    releaseCount: entry.release_count === undefined ? null : numeric(entry.release_count, null),
    similarNames: safeArray(entry.similar_names).map((item) => ({
      name: item?.name || "?", distance: item?.distance ?? null,
    })),
    reasons: safeArray(entry.reasons).map(String),
    lookupError: entry.lookup_error || null,
    llm: entry.llm || null,
  };
}

/** Compact per-finding record built only from fields the engine emitted. */
export function findingFrom(vulnerability, index) {
  const severity = severityOf(vulnerability);
  const pkg = vulnerability?.package || {};
  const key = `${vulnerability?.id || "unknown"}::${packageKey(pkg)}::${index}`;
  return {
    key,
    index,
    id: vulnerability?.id || "unknown",
    aliases: safeArray(vulnerability?.aliases).map(String),
    summary: vulnerability?.summary || "",
    details: vulnerability?.details || "",
    severity,
    band: severity.band,
    fixedVersion: vulnerability?.fixed_version || null,
    package: pkg,
    packageName: pkg.name || "unknown",
    packageVersion: pkg.version || "unknown",
    ecosystem: pkg.ecosystem || purlParts(pkg.purl).type || "unknown",
    purl: pkg.purl || null,
    status: vulnerability?.status || "unknown",
    actionable: String(vulnerability?.status || "") === "affected",
    justification: vulnerability?.justification || null,
    impactStatement: vulnerability?.impact_statement || null,
    evidence: vulnerability?.evidence || {},
    raw: vulnerability,
  };
}

function joinFindingsByPackage(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const key = packageKey(finding.package);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }
  return groups;
}

/**
 * Build the analysis object.
 *
 * `result`  - RepositoryResult from POST /scan (or one entry of a fleet run)
 * `report`  - report.json artifact (optional; used for packages[])
 * `trace`   - trace.json artifact (optional; evidence chains, journeys, stages)
 * `sbom`    - sbom.cdx.json artifact (optional; integrity/license graph data)
 * `vex`     - openvex.json artifact (optional; statements per finding)
 */
export function buildAnalysis({ result, report, trace, sbom, vex, scanId, repositoryId,
                                label, options, artifactsLoaded, artifactErrors }) {
  const vulnerabilities = safeArray(result?.vulnerabilities);
  const findings = vulnerabilities.map(findingFrom);

  // Packages analysed by this scan: report.json is authoritative because it is
  // the inventory the engine actually queried and decided on.
  const inventory = safeArray(report?.packages).length
    ? safeArray(report?.packages)
    : [...new Map(findings.map((f) => [packageKey(f.package), f.package])).values()];

  const components = indexComponents(sbom);
  const registry = new Map();
  for (const entry of safeArray(result?.suspicious_packages)) {
    if (entry?.package) registry.set(packageKey(entry.package), entry);
  }
  const findingsByPackage = joinFindingsByPackage(findings);

  const packages = inventory.map((pkg) => {
    const key = packageKey(pkg);
    const own = findingsByPackage.get(key) || [];
    const sbomMatch = components.byPurl.has(String(pkg.purl || ""))
      ? "purl"
      : components.byNameVersion.has(`${bareName(pkg.name)}@${String(pkg.version || "").toLowerCase()}`)
        ? "name+version" : null;
    const component = components.byPurl.get(String(pkg.purl || ""))
      || components.byNameVersion.get(`${bareName(pkg.name)}@${String(pkg.version || "").toLowerCase()}`)
      || null;
    const actionable = own.filter((finding) => finding.actionable);
    const worst = own.length
      ? own.reduce((acc, finding) => (SEVERITY_RANK[finding.band] < SEVERITY_RANK[acc.band] ? finding : acc), own[0])
      : null;
    return {
      key,
      name: pkg.name || "unknown",
      version: pkg.version || "unknown",
      ecosystem: pkg.ecosystem || purlParts(pkg.purl).type || "unknown",
      purl: pkg.purl || null,
      findings: own,
      findingCount: own.length,
      actionableCount: actionable.length,
      unreachableCount: own.length - actionable.length,
      worstBand: worst ? worst.band : null,
      worstSeverity: worst ? worst.severity : null,
      sbom: componentSignals(component),
      sbomMatch,
      registry: registrySignals(registry.get(key)),
      edges: graphEdges(sbom, pkg, component),
    };
  });

  // SBOM components with no counterpart in the analysed inventory are real data
  // too (a resolver may add transitive entries); they are surfaced separately
  // and never presented as analysed packages.
  const inventoryPurls = new Set(packages.map((pkg) => String(pkg.purl || "")).filter(Boolean));
  const inventoryNames = new Set(packages.map((pkg) => `${bareName(pkg.name)}@${String(pkg.version || "").toLowerCase()}`));
  const sbomOnly = safeArray(sbom?.components).filter((component) => {
    const purl = String(component.purl || "");
    if (purl && inventoryPurls.has(purl)) return false;
    const key = `${bareName(component.name)}@${String(component.version || "").toLowerCase()}`;
    return !inventoryNames.has(key);
  }).map((component) => ({
    name: component.name || "unknown",
    version: component.version || "unknown",
    purl: component.purl || null,
    licenses: safeArray(component.licenses).map((entry) => entry?.license?.id
      || entry?.license?.name).filter(Boolean),
    hashes: safeArray(component.hashes).filter((hash) => hash?.content).length,
  }));

  const vexByStatement = new Map();
  for (const statement of safeArray(vex?.statements)) {
    const id = statement?.vulnerability?.name;
    if (id) vexByStatement.set(id, statement);
  }

  const findingsWithVex = findings.map((finding) => ({
    ...finding,
    vex: vexByStatement.get(finding.id) || null,
    vexMatches: vexByStatement.get(finding.id)
      ? safeArray(vexByStatement.get(finding.id).products)
        .some((product) => String(product?.["@id"] || "") === String(finding.purl || ""))
      : null,
  }));

  const summary = result?.summary || null;
  const detailCounts = {
    total: findingsWithVex.length,
    actionable: findingsWithVex.filter((finding) => finding.actionable).length,
    unreachable: findingsWithVex.filter((finding) => !finding.actionable && finding.status !== "unknown").length,
  };
  const summaryCounts = {
    total: numeric(summary?.total_vulnerabilities, 0),
    actionable: numeric(summary?.actionable, 0),
    unreachable: numeric(summary?.dismissed_unreachable, 0),
    suspicious: numeric(summary?.suspicious_packages, 0),
    noiseReduced: summary?.noise_reduced_percent === undefined ? null : Number(summary.noise_reduced_percent),
  };

  const inconsistencies = [];
  if (summary && (summaryCounts.total !== detailCounts.total
    || summaryCounts.actionable !== detailCounts.actionable)) {
    inconsistencies.push(`report summary (${summaryCounts.total} total / ${summaryCounts.actionable} actionable) `
      + `differs from the ${detailCounts.total} detailed findings in this response`);
  }
  if (trace?.totals?.vulnerability_total_check === false) {
    inconsistencies.push("the engine's own trace flag vulnerability_total_check is false "
      + "(dismissed + actionable does not equal total)");
  }
  if (findingsWithVex.some((finding) => finding.vex && finding.vexMatches === false)) {
    inconsistencies.push("an OpenVEX statement is not attached to this finding's product purl");
  }

  const ecosystemCounts = new Map();
  for (const pkg of packages) {
    ecosystemCounts.set(pkg.ecosystem, (ecosystemCounts.get(pkg.ecosystem) || 0) + 1);
  }

  return {
    scanId: scanId || result?.scan_id || null,
    repositoryId: repositoryId || result?.repository?.id || null,
    label: label || result?.repository?.id || "repository",
    target: report?.target || result?.repository?.path || null,
    status: result?.status || "unknown",
    state: result?.state || "UNKNOWN",
    error: result?.error || null,
    options: options || null,
    scan: result?.scan || null,
    artifacts: result?.artifacts || null,
    artifactNames: result?.artifact_names || {
      report: "report.json", trace: "trace.json", sbom: "sbom.cdx.json", vex: "openvex.json",
    },
    artifactsLoaded: artifactsLoaded || { report: false, trace: false, sbom: false, vex: false },
    artifactErrors: artifactErrors || {},
    //: The four parsed artifacts exactly as the API served them. Kept so the
    //: Reports view can show a file verbatim instead of a reconstruction.
    raw: { report: report || null, trace: trace || null, sbom: sbom || null, vex: vex || null },
    runMetadata: trace?.run_metadata || null,
    stages: safeArray(trace?.stages),
    journeys: safeArray(trace?.journeys),
    chains: safeArray(trace?.evidence_chains),
    totals: trace?.totals || null,
    sbomMetadata: sbom?.metadata || null,
    sbomSpec: sbom ? { bomFormat: sbom.bomFormat || null, specVersion: sbom.specVersion || null,
                      serialNumber: sbom.serialNumber || null, services: safeArray(sbom.services).length } : null,
    unresolved: safeArray(result?.unresolved_dependencies || report?.unresolved_dependencies),
    findings: findingsWithVex,
    packages,
    sbomOnly,
    summary,
    summaryCounts,
    detailCounts,
    inconsistencies,
    ecosystemCounts,
  };
}

function graphEdges(sbom, pkg, component) {
  const dependencies = safeArray(sbom?.dependencies);
  if (!dependencies.length) return { available: false, dependsOn: [], dependedOnBy: [], total: 0 };
  const purl = String(pkg.purl || "");
  const self = dependencies.find((entry) => String(entry.ref || "") === purl
    || String(entry.ref || "") === String(component?.["bom-ref"] || ""));
  const dependedOnBy = dependencies
    .filter((entry) => safeArray(entry.dependsOn).some((ref) => String(ref) === purl))
    .map((entry) => entry.ref)
    .filter(Boolean);
  return {
    available: true,
    dependsOn: safeArray(self?.dependsOn).map(String),
    dependedOnBy,
    total: safeArray(self?.dependsOn).length + dependedOnBy.length,
  };
}

// ---- posture -------------------------------------------------------------

/**
 * SECURITY STATUS — deliberately not a score.
 *
 * The status word is a deterministic function of the engine's own counts and
 * the run outcome. An error, a timeout or a missing artifact can never produce
 * a positive status.
 */
export function postureOf(analysis) {
  if (!analysis) {
    return { word: "NO SCAN LOADED", tone: "idle", basis: "Run a scan to populate the posture.",
             counts: { total: 0, actionable: 0, suspicious: 0, unreachable: 0 } };
  }
  const counts = {
    total: analysis.summaryCounts.total,
    actionable: analysis.summaryCounts.actionable,
    suspicious: analysis.summaryCounts.suspicious,
    unreachable: analysis.summaryCounts.unreachable,
  };
  const basis = `${counts.actionable} actionable · ${counts.suspicious} suspicious · `
    + `${counts.unreachable} dismissed unreachable · ${counts.total} advisories`
    + (analysis.summaryCounts.noiseReduced === null ? "" : ` · ${analysis.summaryCounts.noiseReduced}% noise reduction`);

  if (analysis.error || analysis.status === "failed" || analysis.status === "timeout") {
    return { word: "SCAN NOT COMPLETED", tone: "idle",
             basis: analysis.error?.message || "the engine did not complete this scan",
             counts, incomplete: true };
  }
  if (analysis.status !== "completed") {
    return { word: "STATUS UNKNOWN", tone: "idle", basis: "the API returned no completed state", counts,
             incomplete: true };
  }
  if (analysis.inconsistencies.length) {
    return { word: "REVIEW ADVISED", tone: "warn",
             basis: `${basis} — ${analysis.inconsistencies[0]}`, counts, inconsistent: true };
  }
  if (counts.actionable > 0) {
    return { word: "ACTION REQUIRED", tone: "bad", basis, counts };
  }
  if (counts.suspicious > 0) {
    return { word: "REVIEW REQUIRED", tone: "warn", basis, counts };
  }
  if (counts.total > 0) {
    return { word: "NO ACTIONABLE FINDINGS", tone: "ok",
             basis: `${basis} — every advisory the engine queried was dismissed as unreachable`,
             counts };
  }
  return { word: "NO ADVISORIES FOUND", tone: "idle",
           basis: "the engine's advisory lookup returned nothing for this inventory — not evidence of safety",
           counts };
}

/** The six-stage pipeline the engine records in trace.json, plus run states. */
export const STAGE_LABELS = [
  ["parse", "Parse manifests"],
  ["sbom", "Build SBOM"],
  ["osv_lookup", "Query advisories"],
  ["reachability", "Reachability"],
  ["slopsquat", "Package trust"],
  ["vex_output", "OpenVEX + report"],
];

/** Join helper: find the inventory row behind a finding's package reference. */
export function packageIndex(analysis) {
  const byPurl = new Map();
  const byNameVersion = new Map();
  for (const pkg of safeArray(analysis?.packages)) {
    if (pkg.purl) byPurl.set(String(pkg.purl), pkg);
    byNameVersion.set(`${bareName(pkg.name)}@${String(pkg.version || "").toLowerCase()}`, pkg);
  }
  return {
    byPurl,
    byNameVersion,
    find(reference) {
      if (!reference) return null;
      const purl = String(reference.purl || "");
      if (purl && byPurl.has(purl)) return byPurl.get(purl);
      return byNameVersion.get(`${bareName(reference.name)}@${String(reference.version || "").toLowerCase()}`)
        || null;
    },
  };
}

// ---- search, filter, sort ------------------------------------------------

export function evidenceLocations(finding) {
  const evidence = finding.evidence || {};
  return [...safeArray(evidence.calls), ...safeArray(evidence.import)]
    .filter((item) => item && item.file)
    .map((item) => ({ ...item, isCall: item.kind === "call" }));
}

export function reachabilityStateOf(finding) {
  const evidence = finding.evidence || {};
  const imported = evidence.imported !== undefined
    ? Boolean(evidence.imported)
    : safeArray(evidence.import).length > 0;
  const calls = safeArray(evidence.calls);
  const functions = safeArray(evidence.vulnerable_functions);
  if (!imported) return "not-imported";
  if (!functions.length) return "unknown";
  if (!calls.length) return "no-calls";
  return "calls-found";
}

export function filterFindings(findings, { query = "", severity = [], verdict = "", reachability = "",
                                           ecosystem = "", pkg = "", actionability = "" } = {}) {
  const needle = query.trim().toLowerCase();
  const severitySet = new Set(severity);
  return findings.filter((finding) => {
    if (severitySet.size && !severitySet.has(finding.band)) return false;
    if (verdict && finding.status !== verdict) return false;
    if (actionability === "actionable" && !finding.actionable) return false;
    if (actionability === "unreachable" && finding.actionable) return false;
    if (reachability && reachabilityStateOf(finding) !== reachability) return false;
    if (ecosystem && finding.ecosystem !== ecosystem) return false;
    if (pkg && finding.packageName !== pkg) return false;
    if (!needle) return true;
    return searchableText(finding).includes(needle);
  });
}

function searchableText(finding) {
  const locations = evidenceLocations(finding).map((item) => item.file).join(" ");
  return [
    finding.id, finding.aliases.join(" "), finding.summary, finding.details,
    finding.packageName, finding.packageVersion, finding.purl || "",
    finding.impactStatement || "", finding.justification || "", locations,
  ].join(" ").toLowerCase();
}

export function sortFindings(findings, sort) {
  const { key = "severity", dir = "asc" } = sort || {};
  const factor = dir === "desc" ? -1 : 1;
  const compare = {
    severity: (a, b) => (SEVERITY_RANK[a.band] - SEVERITY_RANK[b.band])
      || a.packageName.localeCompare(b.packageName),
    package: (a, b) => a.packageName.localeCompare(b.packageName)
      || a.id.localeCompare(b.id),
    version: (a, b) => String(a.packageVersion).localeCompare(String(b.packageVersion)),
    id: (a, b) => a.id.localeCompare(b.id),
    verdict: (a, b) => String(a.status).localeCompare(String(b.status))
      || (SEVERITY_RANK[a.band] - SEVERITY_RANK[b.band]),
    reachability: (a, b) => reachabilityStateOf(a).localeCompare(reachabilityStateOf(b)),
    fixed: (a, b) => String(a.fixedVersion || "~").localeCompare(String(b.fixedVersion || "~")),
    trust: (a, b) => trustRank(a) - trustRank(b),
  }[key] || (() => 0);
  return [...findings].sort((a, b) => factor * compare(a, b));
}

/** Lower rank = more concerning trust picture (registry facts only). */
export function trustRank(finding) {
  return finding.actionable ? 0 : 1;
}

export function filterPackages(packages, { query = "", ecosystem = "", findings = "", trust = "" } = {}) {
  const needle = query.trim().toLowerCase();
  return packages.filter((pkg) => {
    if (ecosystem && pkg.ecosystem !== ecosystem) return false;
    if (findings === "actionable" && pkg.actionableCount === 0) return false;
    if (findings === "any" && pkg.findingCount === 0) return false;
    if (findings === "none" && pkg.findingCount > 0) return false;
    if (trust === "suspicious" && !(pkg.registry?.suspicious)) return false;
    if (trust === "registry-unavailable" && !(pkg.registry?.lookupError)) return false;
    if (trust === "no-integrity" && (pkg.sbom?.hashes?.length || 0) > 0) return false;
    if (!needle) return true;
    return [pkg.name, pkg.version, pkg.ecosystem, pkg.purl || "",
            safeArray(pkg.registry?.reasons).join(" "),
            safeArray(pkg.registry?.similarNames).map((item) => item.name).join(" ")]
      .join(" ").toLowerCase().includes(needle);
  });
}

export function sortPackages(packages, sort) {
  const { key = "findings", dir = "desc" } = sort || {};
  const factor = dir === "desc" ? -1 : 1;
  const compare = {
    name: (a, b) => a.name.localeCompare(b.name),
    version: (a, b) => String(a.version).localeCompare(String(b.version)),
    ecosystem: (a, b) => a.ecosystem.localeCompare(b.ecosystem),
    findings: (a, b) => (a.findingCount - b.findingCount) || a.name.localeCompare(b.name),
    actionable: (a, b) => (a.actionableCount - b.actionableCount) || a.name.localeCompare(b.name),
    severity: (a, b) => (SEVERITY_RANK[a.worstBand || "unknown"] - SEVERITY_RANK[b.worstBand || "unknown"])
      || a.name.localeCompare(b.name),
    age: (a, b) => numeric(a.registry?.ageDays, -1) - numeric(b.registry?.ageDays, -1),
    releases: (a, b) => numeric(a.registry?.releaseCount, -1) - numeric(b.registry?.releaseCount, -1),
    trust: (a, b) => (a.registry?.suspicious ? 0 : 1) - (b.registry?.suspicious ? 0 : 1)
      || numeric(a.registry?.ageDays, 99999) - numeric(b.registry?.ageDays, 99999),
  }[key] || (() => 0);
  return [...packages].sort((a, b) => factor * compare(a, b));
}

/** Global search over loaded scan data only (no backend search exists). */
export function searchAll(analysis, query) {
  const needle = query.trim().toLowerCase();
  if (!analysis || needle.length < 2) return [];
  const results = [];
  for (const finding of analysis.findings) {
    const haystack = `${finding.id} ${finding.aliases.join(" ")} ${finding.summary}`.toLowerCase();
    if (haystack.includes(needle)) {
      results.push({ kind: "Finding", label: finding.id, sub: `${finding.packageName} ${finding.packageVersion}`,
                     to: { view: "vulnerabilities", param: finding.key } });
    }
  }
  for (const pkg of analysis.packages) {
    const haystack = `${pkg.name} ${pkg.version} ${pkg.purl || ""}`.toLowerCase();
    if (haystack.includes(needle)) {
      results.push({ kind: "Package", label: pkg.name, sub: `${pkg.version} · ${pkg.ecosystem}`,
                     to: { view: "dependencies", param: pkg.key } });
    }
  }
  for (const finding of analysis.findings) {
    for (const item of evidenceLocations(finding)) {
      if (String(item.file || "").toLowerCase().includes(needle)) {
        results.push({ kind: item.isCall ? "Call site" : "Import",
                       label: `${item.file}${item.line ? `:${item.line}` : ""}`,
                       sub: `${finding.id} · ${finding.packageName}`,
                       to: { view: "vulnerabilities", param: finding.key } });
      }
    }
  }
  for (const entry of analysis.unresolved) {
    const haystack = `${entry.name || ""} ${entry.version_specifier || ""} ${entry.file || ""}`.toLowerCase();
    if (haystack.includes(needle)) {
      results.push({ kind: "Unresolved", label: String(entry.name || "dependency"),
                     sub: `${entry.reason || "unresolved"} · ${entry.version_specifier || "*"}`,
                     to: { view: "dependencies", param: "" } });
    }
  }
  const seen = new Set();
  return results.filter((item) => {
    const id = `${item.kind}:${item.label}:${item.sub}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  }).slice(0, 40);
}

// ---- history -------------------------------------------------------------

/** Compact record kept in the browser so past runs stay navigable. */
export function historyEntry(analysis) {
  return {
    scanId: analysis.scanId,
    repositoryId: analysis.repositoryId,
    label: analysis.label,
    target: analysis.target,
    startedAt: new Date().toISOString(),
    status: analysis.status,
    state: analysis.state,
    counts: analysis.summaryCounts,
    error: analysis.error ? analysis.error.code : null,
  };
}

export function packageSeverityTone(pkg) {
  return toneForBand(pkg.worstBand || "unknown");
}

export function bandFromScore(score) {
  return bandForScore(score);
}

export { SEVERITY_ORDER };

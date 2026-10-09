/* Formatting, severity derivation and verdict vocabulary.
 *
 * Nothing here decides security semantics: verdicts, justification codes and
 * decision sources come from the engine's report.json untouched. The single
 * computed value is a CVSS v3.x *base score derived from the advisory's own
 * vector string* using the published FIRST formula — it is labelled as
 * computed in the UI and the raw vector is always shown next to it.
 */

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];
export const SEVERITY_LABEL = {
  critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", unknown: "UNRATED",
};

/** Engine verdict words (never recomputed in the browser). */
export const VERDICT = {
  affected: { word: "ACTIONABLE", tone: "bad" },
  not_affected: { word: "NOT AFFECTED", tone: "ok" },
  unknown: { word: "UNKNOWN", tone: "idle" },
};

/** OpenVEX justification vocabulary, verbatim codes plus their meaning. */
const JUSTIFICATION = {
  vulnerable_code_not_present:
    "Vulnerable code is not present: the dependency was never imported or required in the scanned source.",
  vulnerable_code_not_in_execute_path:
    "Vulnerable code is not on an execute path: no calls to the advisory's identified vulnerable functions were found.",
  vulnerable_code_cannot_be_controlled_by_adversary:
    "Vulnerable code cannot be controlled by an adversary.",
  component_not_present: "The component is not present in the scanned inventory.",
  inline_mitigations_already_exist: "Inline mitigations already exist.",
};

/** Engine decision_source -> evidence grade. Faithful to the engine's own words. */
const GRADE = {
  "import-check": { word: "DETERMINISTIC", tone: "ok",
                    note: "static import/require scan of the repository" },
  advisory_backticks: { word: "HEURISTIC", tone: "warn",
                        note: "vulnerable functions extracted from advisory text" },
  heuristic: { word: "HEURISTIC", tone: "warn",
               note: "vulnerable functions extracted from advisory text" },
  llm: { word: "LLM-ASSISTED", tone: "info",
         note: "candidate functions suggested by the configured LLM (advisory union preserved)" },
  "llm+advisory_backticks": { word: "LLM + ADVISORY", tone: "info",
                              note: "LLM suggestions unioned with advisory-derived functions" },
  "conservative-default": { word: "CONSERVATIVE DEFAULT", tone: "warn",
                            note: "no function-level data available, treated as affected" },
};

const CSS_SEVERITY = new Set(["critical", "high", "medium", "low", "unknown"]);

// ---- basic formatting ----------------------------------------------------

export function num(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  return new Intl.NumberFormat("en-US").format(Number(value));
}

export function pct(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${number.toFixed(1)}%`;
}

export function bytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size)) return "—";
  const units = ["B", "KiB", "MiB", "GiB"];
  let index = 0;
  let rest = size;
  while (rest >= 1024 && index < units.length - 1) { rest /= 1024; index += 1; }
  return `${rest.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function durationMs(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60000) return `${(value / 1000).toFixed(1)} s`;
  const minutes = Math.floor(value / 60000);
  return `${minutes} min ${Math.round((value % 60000) / 1000)} s`;
}

export function elapsedLabel(seconds) {
  const value = Math.max(0, Math.floor(Number(seconds) || 0));
  const mm = String(Math.floor(value / 60)).padStart(2, "0");
  const ss = String(value % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

export function fmtDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function fmtTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function timeAgo(value) {
  if (!value) return "—";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function days(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  if (number < 365) return `${num(number)} d`;
  return `${(number / 365).toFixed(1)} y`;
}

/** "pkg:pypi/requests@2.19.0" -> {type, namespace, name, version} */
export function purlParts(purl) {
  const value = String(purl || "");
  const match = /^pkg:([^/]+)\/(?:([^/@]+)\/)?([^@/]+)(?:@(.+))?$/.exec(value);
  if (!match) return { type: "", namespace: "", name: value, version: "" };
  return { type: match[1], namespace: match[2] || "", name: match[3], version: match[4] || "" };
}

export function fileLine(item) {
  if (!item) return "";
  const file = String(item.file || "");
  return item.line ? `${file}:${item.line}` : file;
}

export function contextCalls(item) {
  return item && item.kind === "call";
}

// ---- severity ------------------------------------------------------------

function roundUp(value) {
  return Math.ceil(value * 10) / 10;
}

function metric(part) {
  return part ? part.split(":")[1] : "";
}

/**
 * CVSS v3.0/v3.1 base score from a vector string (FIRST specification).
 * Returns null when the vector is not a v3 vector we can score.
 */
export function cvssV3Base(vector) {
  const text = String(vector || "");
  if (!/^CVSS:3\.[01]\//.test(text)) return null;
  const metrics = {};
  for (const chunk of text.split("/").slice(1)) {
    const [key, value] = chunk.split(":");
    if (key && value) metrics[key] = value;
  }
  const required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  if (!required.every((key) => metrics[key])) return null;
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.AV];
  const AC = { L: 0.77, H: 0.44 }[metrics.AC];
  const scopeChanged = metrics.S === "C";
  const PR = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }[metrics.PR]
    : { N: 0.85, L: 0.62, H: 0.27 }[metrics.PR];
  const UI = { N: 0.85, R: 0.62 }[metrics.UI];
  const CIA = { H: 0.56, L: 0.22, N: 0 };
  const c = CIA[metrics.C]; const i = CIA[metrics.I]; const a = CIA[metrics.A];
  if ([AV, AC, PR, UI, c, i, a].some((value) => value === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * AV * AC * PR * UI;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundUp(raw);
}

export function bandForScore(score) {
  if (score === null || score === undefined || Number.isNaN(Number(score))) return "unknown";
  const value = Number(score);
  if (value <= 0) return "unknown";
  if (value < 4.0) return "low";
  if (value < 7.0) return "medium";
  if (value < 9.0) return "high";
  return "critical";
}

/** Human breakdown of a CVSS v3 vector, for the evidence panel. */
export function cvssBreakdown(vector) {
  const labels = {
    AV: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" },
    AC: { L: "Low complexity", H: "High complexity" },
    PR: { N: "No privileges", L: "Low privileges", H: "High privileges" },
    UI: { N: "No user interaction", R: "User interaction required" },
    S: { U: "Scope unchanged", C: "Scope changed" },
    C: { H: "Confidentiality high", L: "Confidentiality low", N: "Confidentiality none" },
    I: { H: "Integrity high", L: "Integrity low", N: "Integrity none" },
    A: { H: "Availability high", L: "Availability low", N: "Availability none" },
  };
  const out = [];
  for (const chunk of String(vector || "").split("/").slice(1)) {
    const [key, value] = chunk.split(":");
    if (labels[key] && labels[key][value]) out.push({ key, value, text: labels[key][value] });
  }
  return out;
}

/**
 * Severity of one vulnerability entry.
 *
 * Precedence: CVSS v3 vector (computed) > numeric score > CVSS v4 vector
 * (shown but not scored) > unrated. `computed` marks a derived base score.
 */
export function severityOf(vulnerability) {
  const entries = Array.isArray(vulnerability?.severity) ? vulnerability.severity : [];
  const sources = entries.map((entry) => ({
    type: String(entry?.type || "unknown"),
    score: entry?.score,
  }));
  const numeric = sources.find((item) => typeof item.score === "number"
    || (typeof item.score === "string" && /^\d+(\.\d+)?$/.test(item.score.trim())));
  const v3 = sources.find((item) => typeof item.score === "string"
    && /^CVSS:3\.[01]\//.test(item.score.trim()));
  const v4 = sources.find((item) => typeof item.score === "string"
    && /^CVSS:(4\.0|2)\//.test(item.score.trim()));

  if (v3) {
    const score = cvssV3Base(v3.score);
    if (score !== null) {
      const band = bandForScore(score);
      return { band, label: SEVERITY_LABEL[band], score, vector: v3.score,
               vectorType: v3.type || "CVSS_V3", basis: "computed base score (CVSS v3 vector)",
               computed: true, sources };
    }
  }
  if (numeric) {
    const score = Number(numeric.score);
    const band = bandForScore(score);
    return { band, label: SEVERITY_LABEL[band], score, vector: null,
             vectorType: numeric.type || "CVSS", basis: `advisory score (${numeric.type || "numeric"})`,
             computed: false, sources };
  }
  if (v4) {
    return { band: "unknown", label: SEVERITY_LABEL.unknown, score: null, vector: v4.score,
             vectorType: v4.type || "CVSS_V4", basis: "CVSS v4 vector (not scored by this UI)",
             computed: false, sources };
  }
  return { band: "unknown", label: SEVERITY_LABEL.unknown, score: null, vector: null,
           vectorType: null, basis: "advisory provided no severity", computed: false, sources };
}

export function toneForBand(band) {
  return CSS_SEVERITY.has(band) ? band : "unknown";
}

// ---- verdict vocabulary --------------------------------------------------

export function verdictOf(vulnerability) {
  const status = String(vulnerability?.status || "").toLowerCase();
  if (status === "affected") return VERDICT.affected;
  if (status === "not_affected") return VERDICT.not_affected;
  return VERDICT.unknown;
}

export function justificationText(code) {
  if (!code) return null;
  return JUSTIFICATION[code] || null;
}

export function gradeOf(source) {
  if (!source) return { word: "UNKNOWN", tone: "idle", note: "decision source not reported" };
  return GRADE[String(source)] || { word: String(source).toUpperCase(), tone: "idle",
                                    note: "decision source reported by the engine" };
}

/**
 * Reachability state derived only from fields the engine already emits:
 * `imported`, `evidence.vulnerable_functions` and `evidence.calls`.
 */
export function reachabilityOf(vulnerability) {
  const evidence = vulnerability?.evidence || {};
  const imported = evidence.imported !== undefined
    ? Boolean(evidence.imported)
    : (Array.isArray(evidence.import) && evidence.import.length > 0);
  const functions = Array.isArray(evidence.vulnerable_functions) ? evidence.vulnerable_functions : [];
  const imports = Array.isArray(evidence.import) ? evidence.import : [];
  const calls = Array.isArray(evidence.calls) ? evidence.calls : [];
  const grade = gradeOf(evidence.function_source);
  let state = "UNKNOWN";
  let note = "No reachability data was reported for this finding.";
  if (!imported) {
    state = "NOT IMPORTED";
    note = "The dependency does not appear in any scanned import or require statement.";
  } else if (!functions.length) {
    state = "UNKNOWN";
    note = "The dependency is imported but the advisory named no vulnerable function to test for.";
  } else if (!calls.length) {
    state = "NO CALLS FOUND";
    note = `Imported, but none of the advisory's functions (${functions.join(", ")}) are called.`;
  } else {
    state = "CALLS FOUND";
    note = `Calls to ${calls.map((item) => item.name).filter(Boolean).join(", ") || "an advisory function"} were found in the scanned source.`;
  }
  return { imported, functions, imports, calls, grade, state, note,
           confidence: evidence.confidence ?? null,
           decisionSource: evidence.function_source || null };
}

/** Small helper used by tables and the command palette. */
export function vulnerabilityLabel(vulnerability) {
  const aliases = Array.isArray(vulnerability?.aliases) ? vulnerability.aliases : [];
  const cve = aliases.find((alias) => /^CVE-/i.test(alias));
  return { id: vulnerability?.id || "unknown", cve: cve || null };
}

export function titleCase(text) {
  return String(text || "").replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

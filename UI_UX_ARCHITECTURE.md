# ChainGuard UI/UX architecture

Status: **implemented and verified against a real scan** (30 advisories / 26 dismissed unreachable /
4 actionable / 1 suspicious package / 86.7 % noise reduction).
Scope: the dashboard and the ML-ready foundation only. No model, no AI detection, no fake data.

---

## 1. Purpose and hard rules

The dashboard is an **interface to the security engine**, never a second opinion about it.

| Rule | How it is enforced in code |
|---|---|
| No security decision in the browser | Verdicts, justification codes, reachability evidence and OpenVEX statements are read from `report.json` / `openvex.json` and rendered as-is. `frontend/js/model.js` never maps `affected` → `not affected` or the reverse. |
| No fabricated results | Every value comes from the API response or one of its artifacts. A field the engine did not emit renders as `Not available` (`components.notAvailable`). |
| No fake progress or scores | The API exposes no stage-level progress, so the scan view shows an explicitly indeterminate indicator (`loadingBlock`) and only reports stage timings that `trace.json` actually recorded. There is no numeric "security score": the hero shows a **SECURITY STATUS** word derived deterministically from the engine's own counts. |
| No AI claims | The AI Risk page states that no model exists. A reserved `risk_assessment` shape is documented (§11) and rendered by `components.riskAssessmentPanel`, which returns nothing while no model result exists. |
| Untrusted data is never markup | Every node is built with `el()`/`textContent` (`frontend/js/dom.js`). The only `innerHTML`-equivalent data in the bundle is the trusted icon path table in `dom.js`. |

---

## 2. Canonical project layout

The single source of truth is this repository root. Nothing was moved during this phase, because the
engine's own tests, the API's default `CHAIN_GUARD_ENGINE_ROOT` and the specification set all resolve
from their current locations:

```
chaingaurd/                        <- canonical root (API, dashboard, docs, demo)
├── chainguard_api/                <- the ONLY API (FastAPI), mounts this dashboard at /ui
├── frontend/                      <- the ONLY dashboard (this document)
├── software supply chain mvp/     <- the ONLY engine (chainguard_mvp) + its specification set
│   ├── chainguard_mvp/            <- real scanner, never modified by this phase
│   ├── tests/                     <- 25 engine tests
│   └── ARCHITECTURE.md · CLI_CONTRACT.md · DECISIONS.md · PROJECT_SPEC.md · SECURITY_MODEL.md
│       · TEST_STRATEGY.md · THREAT_MODEL.md · README.md
├── demo_attack_sim/               <- attack simulation, untouched
└── UI_UX_ARCHITECTURE.md · CLEANUP_REPORT.md · P1_REMEDIATION_REPORT.md
```

The engine directory name contains a space and lives one level below the root, which is why the API
resolves it through `CHAIN_GUARD_ENGINE_ROOT` (default `<root>/software supply chain mvp`) rather than
by a hard-coded path. The frontend is served at `/ui` by that same API (`CHAIN_GUARD_FRONTEND_DIR`),
so the browser and the scanner share one origin and no second server exists. Moving the specification
documents into a `specs/` folder would break the engine's relative references and its tests for no
functional gain, so they stay with the engine and are the canonical specification set.

## 3. Information architecture

```
Overview        security posture, top risks, dismissed advisories, pipeline, run provenance
Scans           start a scan, honest progress, fleet results, history, reopen by scan id
Dependencies    inventory joined with SBOM integrity metadata and registry facts
Vulnerabilities findings table + per-finding investigation drawer
Reachability    execute-path evidence per advisory + package journey from trace.json
Trust           integrity / registry / provenance signals that actually exist
Reports         the four artifacts, served read-only, with per-artifact summaries
─────────────
AI Risk  (planned · NOT IMPLEMENTED)
Fleet    (planned · PARTIAL — multi-repository scanning exists, portfolio view does not)
Settings (planned · READ ONLY — configuration lives in the API environment)
```

Routes are hash-based and shareable: `#/overview`, `#/dependencies`, `#/vulnerabilities`,
`#/vulnerabilities/<finding key>` (opens the investigation drawer), `#/reports`, `#/scans`,
`#/reachability`, `#/trust`, `#/ai-risk`, `#/fleet`, `#/settings`.

```
frontend/
  index.html
  styles/   tokens.css · base.css · shell.css · components.css
  js/       dom.js · format.js · api.js · model.js · components.js · router.js · app.js
  js/views/ common.js · overview.js · scans.js · dependencies.js · vulnerabilities.js
            reachability.js · trust.js · reports.js · planned.js
```

---

## 4. Page definitions

### 3.1 Overview — security posture
* **Hero** (`postureMeter`): the status word (`ACTION REQUIRED`, `REVIEW REQUIRED`,
  `NO ACTIONABLE FINDINGS`, `NO ADVISORIES FOUND`, `SCAN NOT COMPLETED`, `STATUS UNKNOWN`,
  `REVIEW ADVISED` when the report is internally inconsistent) plus the engine summary as a meter:
  actionable · suspicious packages · dismissed unreachable · total advisories · noise reduction.
  The word is a pure function of `summary` + run status (`model.postureOf`); an error, timeout or
  missing artifact can never produce a positive status, and "no advisories" uses a neutral tone with
  the note that it is *not* evidence of safety.
* **Top risks** — actionable findings, severity-sorted, paginated (10 per page), with the compact
  evidence path. Row click opens the investigation drawer.
* **Dismissed as unreachable** — the noise-reduction record with each finding's own justification.
* **Risk summary** — actionable count per severity band, suspicious packages with the registry reason,
  unreachable count, registry lookups that failed.
* **Evidence pipeline** — the six stages the engine records (`parse`, `sbom`, `osv_lookup`,
  `reachability`, `slopsquat`, `vex_output`) with in/out item counts and durations.
* **Run provenance** — scan id, repository id, target, status/state, exit code, engine + Python
  version, flags, and the load state of each artifact. A scan reopened from artifacts says so and
  explains that the exit code is unknown.

### 3.2 Scans
Repository path, scan label, optional `--diff <git ref>`, the three real CLI switches
(`--no-llm`, `--fail-on-actionable`, `--dashboard`), and optional extra paths that switch the request to
`POST /scan/fleet`. While running: an indeterminate indicator with an elapsed timer, the stage list
(marked pending) and the sentence explaining that the API reports no stage progress. Afterwards:
a concise result summary with deep links, fleet rows (status, findings, failure reason, open results),
browser-only history with **Reopen**, and a form to reopen any scan by scan id + repository id.

### 3.3 Dependencies
The analysed inventory (report.json `packages`) joined by purl → name+version to SBOM component
metadata and to the registry inspection the scan recorded. Columns: package/version/ecosystem,
findings (with actionable split), reachability rollup, trust badge, worst severity, SBOM graph edges
(`N out · M in`, `isolated node`, or `no graph in SBOM`), registry status and age. Two disclosure
panels follow: **unresolved dependency declarations** (no single exact version ⇒ no advisory lookup was
possible) and **SBOM inventory only** (components that were never advisory-analysed).

### 3.4 Vulnerabilities + investigation
Sortable, filterable table (severity toggles, verdict, reachability state, ecosystem, actionability,
text search) and a drawer that shows, in order: verdict banner (verdict + severity + evidence grade) →
identity (id, aliases, package, installed version, fixed version, **affected range: explicitly not
emitted by this engine**) → severity with the CVSS vector and its metrics → reachability path →
evidence (advisory functions, import sites, call sites) → description → recommended action →
OpenVEX statement → trace/trust provenance → the raw `report.json` entry verbatim.

### 3.5 Reachability
Counts by evidence state (reachable / imported-not-called / never imported / no function data),
paginated evidence-path cards built by `components.reachabilityPath` from the engine's own import and
call evidence, a **package journey** table from `trace.json` (`journeys[].events`), and a panel that
documents the decision-source vocabulary verbatim.

### 3.6 Trust
Only signals that exist: registry existence/status, lookup failures (reported as unknown, never as
safe), package age, release count, typosquat-proximity hints, SBOM integrity digests (**recorded, not
verified**), declared licences, distribution references, SBOM graph edges. Missing capabilities are
listed as `PLANNED` / `COMING SOON` cards. No score, ratio or colour-coded verdict is computed.

### 3.7 Reports
One row per real artifact with on-disk path, availability and View/Download actions wired to the
read-only artifact endpoint, a per-artifact summary, an **Inspect** disclosure that prints the parsed
artifact exactly as served (truncated with an explicit notice and a link to the raw file), and the
engine console output (stdout/stderr as returned by the scan response, with the note that the API
serves only four JSON artifacts and deliberately not the logs).

---

## 5. Component architecture

| Module | Responsibility |
|---|---|
| `dom.js` | `el()` element builder (properties, events, dataset), `icon()` trusted SVG table, `shorten()`. |
| `format.js` | Numbers/percent/duration/time formatting, CVSS v3 base-score computation, severity bands, verdict and justification vocabulary, decision-source grades, reachability state derivation, purl parsing. |
| `api.js` | `getHealth`, `postScan`, `postFleet`, `artifactUrl`, `loadArtifacts`; `ApiError` with the API's own error codes; `describeError()` for every documented failure mode. |
| `model.js` | `buildAnalysis()` — normalizes one scan (report + trace + sbom + openvex + API response) into findings, packages, joins, counts, inconsistencies; `postureOf()`; filters, sorts, `searchAll()`; browser history entries. |
| `components.js` | Badges, panels, tables + pagination, posture meter, evidence chain, reachability path builder, states, callouts, plan grid, trust badges/facts, stage strip. |
| `router.js` | View registry, hash parsing/formatting. |
| `app.js` | Shell (sidebar/topbar), routing, scan state machine, drawer, command palette, toasts, health polling, per-view UI state, focus preservation across re-render. |
| `views/*` | One `render(ctx) -> Node` per page, using the shared helpers. |

`ctx` (built per render in `app.js`) carries `state`, `analysis`, `posture`, `route`, the current
view's persisted `ui` state with `setUi()`, `searchControl()`, the shared filters/sorts/path helpers and
`actions` (`navigate`, `openFinding`, `closeFinding`, `openPackageFindings`, `runScan`, `cancelScan`,
`loadScanById`, `viewArtifact`, `downloadArtifact`, `toast`, `refreshHealth`, `clearHistory`).

**Derived, not invented.** Two values are computed in the browser because the engine emits only the
inputs, and both are labelled in the UI: the CVSS v3.1 base score from the advisory's own vector
(FIRST formula, shown next to the raw vector) and the SECURITY STATUS word from the engine's counts.
Everything else — existence, affected status, reachability, justification, VEX, evidence — is passed
through untouched.

---

## 6. API data mapping

| UI element | Source |
|---|---|
| Posture counts, noise reduction | `POST /scan` → `summary` |
| Verdict, justification, impact statement | `vulnerabilities[].status` / `.justification` / `.impact_statement` |
| Severity, fixed version, aliases | `vulnerabilities[].severity` / `.fixed_version` / `.aliases` |
| Reachability, import sites, call sites, advisory functions, evidence grade, LLM confidence | `vulnerabilities[].evidence` (`imported`, `import[]`, `calls[]`, `vulnerable_functions[]`, `function_source`, `confidence`) |
| Suspicious packages, registry facts | `suspicious_packages[]` (`suspicious`, `status`, `exists`, `created`, `age_days`, `release_count`, `similar_names[]`, `reasons[]`, `lookup_error`) |
| Unresolved declarations | `unresolved_dependencies[]` |
| Inventory | `report.json` → `packages[]` (authoritative: what was actually queried) |
| Pipeline stages, evidence chains, journeys, totals, run metadata | `trace.json` |
| Integrity digests, licences, distribution refs, dependency edges, tool version | `sbom.cdx.json` |
| Machine-readable statements per finding | `openvex.json` |
| Engine health, path, entrypoint, degradation | `GET /health` |
| Artifact bytes | `GET /scans/{scanId}/repositories/{repoId}/artifacts/{name}` (allowlist: `report.json`, `trace.json`, `sbom.cdx.json`, `openvex.json`) |

**Consistency check.** `buildAnalysis` compares the engine's summary, the detailed finding rows and
`trace.totals.vulnerability_total_check`; a disagreement produces a `REVIEW ADVISED` status and a
visible callout instead of silently trusting one number.

---

## 7. Error states

`api.describeError` maps every documented code to a title, an explanation and a remedy, and the state
type never claims safety:

| Code | Shown as |
|---|---|
| `API_UNAVAILABLE` | "API unavailable … this is not a safe state" + the uvicorn command |
| `ENGINE_UNAVAILABLE` | "Security engine unavailable" + point to `GET /health` |
| `INVALID_REPOSITORY` | "Invalid repository path" + the allowed-root rule |
| `INVALID_REPOSITORY_ID` | "Invalid scan label" + the id pattern |
| `SCAN_TIMEOUT` | "Scan timed out" + `SCAN_TIMEOUT_SECONDS` guidance |
| `SCAN_INVALID_INPUT` | "Engine rejected the target" (exit code 2) |
| `OUTPUT_MISSING` | "No supported manifest" (`report.json` missing) |
| `SCAN_FAILED` / `ENGINE_EXECUTION_FAILED` | "Scan failed" + where the captured output went |
| `ARTIFACT_MISSING` / `ARTIFACT_ERROR` | per-artifact row status; nothing is substituted |
| fleet partial failure | per-repository row with status and reason; fleet status `partial` |
| unexpected view exception | `VIEW ERROR` boundary state with a link back to the overview |

## 8. Empty states

No scan loaded · scan in progress · no findings from the engine · no finding matches the filters ·
no actionable findings · nothing was dismissed · no unresolved declarations · SBOM and inventory agree ·
no scans yet · no reports generated · no trust information · no journey recorded · no model assessment.
Each one states what is missing and, where relevant, that **empty ≠ safe**.

---

## 9. Accessibility

Semantic landmarks (`aside`, `header`, `main`, `nav`, `table` with `scope="col"`), skip link,
`:focus-visible` outlines, keyboard-operable tables (rows are focusable and respond to Enter/Space),
`aria-sort` on sorted headers, `aria-pressed` severity toggles, `role="dialog"` + `aria-modal` drawer and
palette with Escape to close, `aria-live` route announcements and toasts, severity communicated by
glyph **and** word **and** colour (never colour alone), 4.5:1+ body text on panel surfaces, and full
`prefers-reduced-motion` support (spinner, sweep bar, skeleton pulse and all transitions collapse).

## 10. Performance

Every list is paginated (25 rows in tables, 10 on the overview and reachability cards) so DOM size is
bounded regardless of scan size; only the current page is constructed. Filtering and sorting operate on
plain arrays in `model.js`, tables are rebuilt per render (measured acceptable at the current scale),
search is debounced, and no virtualisation library was added — the pagination already caps the node
count. No third-party runtime dependency exists: the entire dashboard is ~135 KB of hand-written
ES modules plus four stylesheets.

## 11. Future ML integration (prepared, not implemented)

The frontend reserves a per-finding `risk_assessment` shape:
`model_version`, `risk_probability`, `risk_class`, `confidence`, `top_features`, `explanation`.
When the API returns one, the intended hierarchy is:

```
DETERMINISTIC VERDICT → EVIDENCE → REACHABILITY → TRUST → ML RISK ASSESSMENT
```

Until then the AI Risk page states that no probability, confidence or feature attribution exists, and
nothing anywhere renders a percentage, a "94 % AI risk" style claim, or an AI badge. The deterministic
verdict always renders first and remains primary.

## 12. Future trust integration

Signals the engine does not yet produce are listed as planned cards rather than estimated: signatures
and attestations (Sigstore-style), SLSA provenance levels, maintainer/ownership history, release-health
trends, package reputation and behavioural or malware analysis. Adding one means adding a field to the
engine's report and a row to `trustFacts()`; the view needs no redesign.

## 13. Design principles

1. **Evidence before opinion.** The path from application → source → call → dependency → advisory is
   the product's differentiator, drawn from recorded evidence and nothing else.
2. **Deterministic first.** Verdict, reachability, justification and VEX are the engine's; the UI's job
   is to make them auditable, including the raw report entry.
3. **Honest silence.** `Not available` beats a guess; `UNKNOWN` never renders as safe; an error never
   renders green.
4. **Severity is the only saturation.** Red/orange is reserved for real severity, green for a verified
   healthy state the engine asserted, cyan for system information.
5. **Density with air.** Tabular numerics, one accent per surface, hairline rules and consistent
   spacing tokens rather than decorative cards, gradients or animation.
6. **No dead buttons.** Anything not implemented is labelled `COMING SOON` / `PLANNED` / `NOT
   IMPLEMENTED` on a page that explains why.

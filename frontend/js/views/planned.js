/* Planned capabilities.
 *
 * These pages exist so the navigation is honest: nothing here is functional,
 * nothing is faked, and no number on them is invented. Each card either states
 * that the capability does not exist yet or shows data the engine really does
 * provide today.
 */

import { el, frag } from "../dom.js";
import { callout, panel, planGrid, stateBlock } from "../components.js";
import { num } from "../format.js";
import { pageHead } from "./common.js";

const PAGES = {
  "ai-risk": {
    title: "AI Risk",
    sub: "Planned: model-assisted risk assessment on top of the deterministic verdict",
    status: "NOT IMPLEMENTED",
    body: "ChainGuard does not run a model. No risk probability, no confidence and no feature "
      + "attribution exists in this build, so this page shows none: an invented score would be worse "
      + "than an empty page. The deterministic verdict, its evidence and its reachability path remain "
      + "the only source of security decisions.",
    panels: [
      ["Contract already reserved", [
        "The frontend data model reserves a `risk_assessment` object per finding with "
        + "`model_version`, `risk_probability`, `risk_class`, `confidence`, `top_features` and "
        + "`explanation`. When the API returns it, the assessment panel renders underneath the "
        + "deterministic evidence — never instead of it.",
      ]],
    ],
    plans: [
      ["Static behavioural features", "Build the feature set before any model: install hooks, obfuscated "
        + "payloads, network calls at import time, filesystem and environment access.", "PLANNED"],
      ["Dataset construction", "Label features against known-good and known-malicious packages with the "
        + "engine's own verdicts as ground truth.", "PLANNED"],
      ["Model + explainability", "Train and explain a model; publish per-finding feature attribution so "
        + "the UI can show why a score moved.", "PLANNED"],
      ["UI activation", "This page becomes real only when a model version is attached to every score.",
       "PLANNED"],
    ],
  },
  fleet: {
    title: "Fleet",
    sub: "Planned: portfolio view across repositories, accounts and teams",
    status: "PARTIAL",
    body: "The API already scans several repositories in one bounded-concurrency request "
      + "(POST /scan/fleet) and the Scans page uses it. What does not exist yet is a portfolio view: "
      + "no cross-run history is stored server-side, no ownership model, no trend data.",
    plans: [
      ["Persistent scan store", "The API keeps no scan index; history lives in the browser session only.",
       "PLANNED"],
      ["Ownership and grouping", "Repositories, teams and environments.", "PLANNED"],
      ["Trends", "Posture over time per repository.", "PLANNED"],
    ],
  },
};

export function render(ctx) {
  const config = PAGES[ctx.route.view] || PAGES["ai-risk"];
  const { analysis } = ctx;

  const live = [];
  if (ctx.route.view === "fleet" && analysis) {
    live.push(panel({
      title: "What this build can already do",
      body: [
        callout("info", "Multi-repository scanning is available today",
          `${num(analysis.packages.length)} packages from ${analysis.label} were analysed in the most recent `
          + "scan. Add more paths on the Scans page to scan several repositories in one bounded-concurrency "
          + "request; each repository gets its own isolated output directory and its own result row."),
        el("div", { class: "state-actions", style: { marginTop: "var(--sp-3)" } },
          el("a", { class: "btn btn-primary", href: "#/scans", text: "Open the Scans page" })),
      ],
    }));
  }

  return frag(
    pageHead({ title: config.title, sub: config.sub,
               actions: [el("span", { class: "badge badge--warn", text: config.status })] }),
    el("div", { style: { marginTop: "var(--sp-4)" } },
      stateBlock({ tone: "idle", mark: "◌", title: `${config.title} is not implemented`,
                   body: config.body })),
    el("div", { style: { marginTop: "var(--sp-4)" } }, live),
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({ title: "Planned capability", note: "no functionality behind these cards yet",
              body: [planGrid(config.plans.map(([name, body, status]) => ({ name, body, state: status })))] })));
}

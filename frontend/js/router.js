/* View registry and hash routing.
 *
 * Routes are deliberately simple and shareable:
 *   #/overview
 *   #/vulnerabilities/<finding key>      (opens the investigation drawer)
 *   #/reports  #/dependencies  #/reachability  #/trust  #/scans
 *   #/ai-risk  #/fleet  #/settings         (honest "not implemented" pages)
 */

import * as overview from "./views/overview.js";
import * as scans from "./views/scans.js";
import * as dependencies from "./views/dependencies.js";
import * as vulnerabilities from "./views/vulnerabilities.js";
import * as reachability from "./views/reachability.js";
import * as trust from "./views/trust.js";
import * as reports from "./views/reports.js";
import * as planned from "./views/planned.js";
import * as settings from "./views/settings.js";

export const VIEWS = {
  overview: { label: "Overview", glyph: "overview", render: overview.render,
              blurb: "Posture, top risks and run provenance" },
  scans: { label: "Scans", glyph: "scans", render: scans.render,
           blurb: "Start a scan, follow it, reopen earlier runs" },
  dependencies: { label: "Dependencies", glyph: "dependencies", render: dependencies.render,
                  blurb: "Inventory with reachability, trust and SBOM joins" },
  vulnerabilities: { label: "Vulnerabilities", glyph: "vulnerabilities", render: vulnerabilities.render,
                     blurb: "Every advisory with its verdict and evidence" },
  reachability: { label: "Reachability", glyph: "reachability", render: reachability.render,
                  blurb: "Execute-path evidence per finding" },
  trust: { label: "Trust", glyph: "trust", render: trust.render,
           blurb: "Integrity, registry and provenance signals" },
  reports: { label: "Reports", glyph: "reports", render: reports.render,
             blurb: "The four scanner artifacts, as served" },
  "ai-risk": { label: "AI Risk", glyph: "vulnerabilities", render: planned.render, planned: true,
               blurb: "Not implemented — no model exists in this build" },
  fleet: { label: "Fleet", glyph: "scans", render: planned.render, planned: true,
           blurb: "Portfolio view — planned" },
  settings: { label: "Settings", glyph: "lock", render: settings.render,
              blurb: "API status and the access token this deployment requires" },
};

export const PRIMARY_NAV = ["overview", "scans", "dependencies", "vulnerabilities",
                            "reachability", "trust", "reports"];
export const PLANNED_NAV = ["ai-risk", "fleet"];
export const DEFAULT_VIEW = "overview";

export function hashFor(view, param = null) {
  const name = VIEWS[view] ? view : DEFAULT_VIEW;
  return param ? `#/${name}/${encodeURIComponent(param)}` : `#/${name}`;
}

export function parseHash(hash) {
  const raw = String(hash || "").replace(/^#\/?/, "");
  if (!raw) return { view: DEFAULT_VIEW, param: null };
  const [name, ...rest] = raw.split("/");
  const view = VIEWS[name] ? name : DEFAULT_VIEW;
  let param = rest.join("/") || null;
  if (param) {
    try { param = decodeURIComponent(param); } catch { param = null; }
  }
  return { view, param };
}

/** The findings drawer lives on the vulnerabilities route as a path parameter. */
export function isFindingRoute(route) {
  return route.view === "vulnerabilities" && Boolean(route.param);
}

export function titleFor(view, analysis) {
  const label = VIEWS[view]?.label || "ChainGuard";
  return analysis ? `ChainGuard · ${label} · ${analysis.label}` : `ChainGuard · ${label}`;
}

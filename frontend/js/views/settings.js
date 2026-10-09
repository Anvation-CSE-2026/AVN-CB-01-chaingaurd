/* Settings: only real configuration.
 *
 * Two things here are genuinely controllable from the browser:
 *   1. the access token an authenticated deployment requires (kept in memory);
 *   2. nothing else — every other setting is an API environment variable and
 *      is listed for reference, not offered as a toggle.
 */

import { el, frag } from "../dom.js";
import { button, callout, kvList, panel } from "../components.js";
import { hasAccessToken } from "../api.js";
import { pageHead } from "./common.js";

const ENV_VARS = [
  ["CHAIN_GUARD_API_TOKEN", "Access token. When set, scan, artifact and remote routes require it."],
  ["CHAIN_GUARD_API_TOKEN_FILE", "Same, read from a file (one trailing newline ignored)."],
  ["CHAIN_GUARD_ALLOWED_ROOT", "Repositories must resolve inside this root."],
  ["CHAIN_GUARD_SCAN_WORKSPACE", "Where scan outputs are written."],
  ["MAX_CONCURRENT_SCANS", "Bounded worker pool size."],
  ["SCAN_TIMEOUT_SECONDS", "Per-repository engine timeout."],
  ["CHAIN_GUARD_MAX_REQUEST_BYTES", "Largest accepted request body."],
  ["CHAIN_GUARD_NO_LLM", "Passes --no-llm to the engine."],
  ["CHAIN_GUARD_REMOTE_ENABLED", "Remote execution gate; off unless explicitly enabled."],
];

export function render(ctx) {
  const { state, actions } = ctx;
  const health = state.health;
  const authRequired = health?.auth?.required ?? null;
  const tokenPresent = hasAccessToken();

  const input = el("input", {
    type: "password",
    name: "access-token",
    autocomplete: "off",
    spellcheck: "false",
    "aria-label": "Access token",
    placeholder: "paste the access token",
  });
  const save = () => {
    const value = input.value;
    if (!value.trim()) {
      actions.toast("error", "Token is empty", "Enter the token before saving.");
      return;
    }
    actions.saveAccessToken(value);
    input.value = "";
  };
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      save();
    }
  });

  const apiRows = [
    ["API status", health ? health.status : (state.healthError ? "unreachable" : "checking")],
    ["Engine", health ? health.engine?.implementation : null],
    ["Engine path", health?.engine?.path, { mono: true, breakAll: true }],
    ["Access token required", authRequired === null ? null : (authRequired ? "yes" : "no")],
    ["Remote node", health?.remote ? (health.remote.configured ? health.remote.node : "not configured") : null],
  ];

  const tokenBody = [
    authRequired === false
      ? callout("info", "This API does not require a token",
          "The deployment has no CHAIN_GUARD_API_TOKEN set, so every route is open to whoever can reach it.")
      : null,
    authRequired === null
      ? callout("info", "Checking the API", "The token requirement is read from GET /health.")
      : null,
    kvList([["This tab", tokenPresent ? "token held in memory" : "no token set"]]),
    authRequired
      ? el("div", { class: "toolbar-search", style: { marginTop: "var(--sp-3)" } }, input)
      : null,
    authRequired
      ? el("div", { class: "state-actions", style: { marginTop: "var(--sp-3)" } },
          button("Save token", { onClick: save, variant: "primary" }),
          button("Forget token", { onClick: () => actions.clearAccessToken(), variant: "quiet",
                                   disabled: !tokenPresent }))
      : null,
    el("p", { class: "field-hint", style: { marginTop: "var(--sp-3)" },
              text: "The token is sent only as an Authorization header to this API. It is never stored in "
                + "the browser, written to the URL or shown again after saving." }),
  ];

  return frag(
    pageHead({ title: "Settings", sub: "Live API status and the access token this deployment requires" }),
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({ title: "API connection", note: "GET /health", body: [kvList(apiRows)] })),
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({ title: "Access token", note: "memory only, this tab", body: tokenBody })),
    el("div", { style: { marginTop: "var(--sp-4)" } },
      panel({
        title: "Server configuration",
        note: "environment variables, not UI toggles",
        body: [
          callout("info", "Changed on the server, not here",
            "These are read by the API process at startup. Restart the service after changing them."),
          el("dl", { class: "kv", style: { marginTop: "var(--sp-3)" } },
            ENV_VARS.flatMap(([name, description]) => [
              el("dt", { class: "mono", text: name }),
              el("dd", { text: description }),
            ])),
        ],
      })));
}

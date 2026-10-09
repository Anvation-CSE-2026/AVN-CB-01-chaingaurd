/* Minimal DOM helpers.
 *
 * Every view builds elements with el()/text, so untrusted scan data (package
 * names, advisory text, file paths) is never interpreted as HTML. The only
 * innerHTML assignments in this app come from the trusted icon table below.
 */

const ICON_PATHS = {
  overview: "M3 3h7v7H3zM14 3h7v4h-7zM14 10h7v11h-7zM3 13h7v8H3z",
  scans: "M12 3a9 9 0 1 0 9 9M12 7v5l4 2M21 3l-6 6",
  dependencies: "M3 7l9-4 9 4-9 4zM3 12l9 4 9-4M3 17l9 4 9-4",
  vulnerabilities: "M12 3l9 16H3zM12 9v5M12 16.5v.5",
  reachability: "M5 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM19 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM7 17c4 0 4-6 10-6",
  trust: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6zM9 12l2 2 4-4",
  reports: "M6 3h8l4 4v14H6zM14 3v5h5M9 13h6M9 17h4",
  search: "M10 4a6 6 0 1 0 0 12 6 6 0 0 0 0-12zM15 15l5 5",
  close: "M6 6l12 12M18 6L6 18",
  chevron: "M9 6l6 6-6 6",
  external: "M14 4h6v6M20 4l-8 8M18 14v6H4V6h6",
  download: "M12 4v10m0 0l4-4m-4 4l-4-4M5 20h14",
  menu: "M4 7h16M4 12h16M4 17h16",
  refresh: "M20 12a8 8 0 1 1-3-6.2M20 4v5h-5",
  clock: "M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16zM12 8v4l3 2",
  arrow: "M5 12h14M13 6l6 6-6 6",
  lock: "M7 11V8a5 5 0 0 1 10 0v3M5 11h14v9H5z",
};

const SVG_NS = "http://www.w3.org/2000/svg";

/** Trusted icon element (path data is a local constant, never user input). */
export function icon(name, size = 16) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", ICON_PATHS[name] || ICON_PATHS.overview);
  svg.appendChild(path);
  return svg;
}

/**
 * el("div", {class: "panel", onclick: fn, dataset: {k: v}, attrs: {role: "img"}},
 *    "text", el("span"), null)
 *
 * Children: strings become text nodes, nodes are appended, null/undefined and
 * false are skipped so `cond && el(...)` works inline.
 */
export function el(tag, props = null, ...children) {
  const node = document.createElement(tag);
  if (props && (typeof props !== "object" || props.nodeType)) {
    children.unshift(props);
    props = null;
  }
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class" || key === "className") node.className = value;
    else if (key === "text") node.textContent = String(value);
    else if (key === "style" && typeof value === "object") Object.assign(node.style, value);
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "attrs") for (const [a, v] of Object.entries(value)) {
      if (v !== null && v !== undefined && v !== false) node.setAttribute(a, String(v));
    }
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value);
    } else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

export function append(parent, children) {
  for (const child of children.flat(4)) {
    if (child === null || child === undefined || child === false || child === true) continue;
    parent.appendChild(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return parent;
}

export function frag(...children) {
  return append(document.createDocumentFragment(), children);
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function mount(parent, ...children) {
  clear(parent);
  return append(parent, children);
}

/** Truncate long strings for dense table cells (full value stays in the title). */
export function shorten(text, max = 90) {
  const value = String(text ?? "");
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

// Sightline dashboard. Vanilla JS, no build step, no third-party code.
// SECURITY: every captured string is attacker-controlled. Build DOM with el()/textContent only;
// never assign innerHTML. The CSP forbids inline script as a second line of defence.
"use strict";

const $ = (id) => document.getElementById(id);
const state = { calls: [], filter: null, query: "", paused: false, selected: null, tab: "conv", window: "24h", setup: null };

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "dataset") Object.assign(n.dataset, v);
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}
const svg = (tag, attrs) => {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  return n;
};

// ---------------------------------------------------------------- formatting
const nf = new Intl.NumberFormat();
const fmtInt = (n) => (n === null || n === undefined ? "—" : nf.format(n));
const fmtTok = (n) => {
  if (n === null || n === undefined) return "—";
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(0) + "k";
  return nf.format(n);
};
const fmtUsd = (v) => {
  if (v === null || v === undefined) return "—";
  if (v === 0) return "$0";
  if (v < 0.01) return "$" + v.toFixed(4);
  if (v < 100) return "$" + v.toFixed(2);
  return "$" + nf.format(Math.round(v));
};
const fmtMs = (v) => (v === null || v === undefined ? "—" : v < 1000 ? Math.round(v) + "ms" : v < 10000 ? (v / 1000).toFixed(2) + "s" : Math.round(v / 1000) + "s");
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const api = (path) => fetch(path, { headers: { Accept: "application/json" } }).then((r) => {
  if (!r.ok) throw new Error(r.status);
  return r.json();
});

// ---------------------------------------------------------------- traffic table
function statusCell(c) {
  const out = [];
  if (c.action === "blocked") out.push(el("span", { class: "badge bad" }, "blocked"));
  else if (c.error && !c.status) out.push(el("span", { class: "badge bad" }, "error"));
  else if (c.status >= 400) out.push(el("span", { class: "badge warn" }, String(c.status)));
  else if (c.status) out.push(el("span", { class: "badge ok" }, String(c.status)));
  const nFind = (c.findings || []).reduce((a, f) => a + (f.count || 1), 0);
  if (c.action === "redacted" && nFind) out.push(el("span", { class: "badge warn" }, `${nFind} redacted`));
  else if (nFind) out.push(el("span", { class: "badge", title: "Detected but not redacted (local model; data stays on this Mac)" }, `${nFind} flagged`));
  if (c.usage_source === "none" && c.action !== "blocked" && !c.error && c.status < 400) out.push(el("span", { class: "badge", title: "No parser for this endpoint yet" }, "usage ?"));
  return out;
}

function costCell(c) {
  if (c.usd === null || c.usd === undefined) return el("span", { class: "muted" }, "—");
  if (c.usd === 0 && c.shadow_usd) return el("span", { title: `Local model. The same tokens on a hosted model ≈ ${fmtUsd(c.shadow_usd)}` }, el("span", { class: "muted" }, "≈" + fmtUsd(c.shadow_usd)));
  return fmtUsd(c.usd);
}

function rowFor(c, fresh) {
  const tr = el("tr", { class: (fresh ? "new " : "") + (state.selected === c.id ? "sel" : ""), dataset: { id: c.id }, onclick: () => openDetail(c.id) },
    el("td", { class: "mono muted" }, fmtTime(c.ts)),
    el("td", {}, el("span", { class: "prov", dataset: { p: c.provider || "" } }, el("i"), c.provider || "?")),
    el("td", { class: "mono", title: c.model || "" }, c.model || el("span", { class: "muted" }, c.endpoint || "—")),
    el("td", { title: c.tag || c.client || "" }, c.tag ? el("span", { class: "tag" }, c.tag) : (c.client || el("span", { class: "muted" }, "—"))),
    el("td", { class: "num" }, fmtTok(c.input_tokens)),
    el("td", { class: "num" }, fmtTok(c.output_tokens)),
    el("td", { class: "num" }, costCell(c)),
    el("td", { class: "num muted" }, c.stream ? fmtMs(c.ttft_ms) : "—"),
    el("td", { class: "num" }, fmtMs(c.latency_ms)),
    el("td", {}, statusCell(c)),
  );
  return tr;
}

function visible(c) {
  if (state.filter && c.provider !== state.filter) return false;
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return [c.model, c.client, c.tag, c.provider, c.endpoint].some((v) => v && String(v).toLowerCase().includes(q));
}

function renderRows(freshId) {
  const body = $("rows");
  const rows = state.calls.filter(visible).slice(0, 500).map((c) => rowFor(c, c.id === freshId));
  body.replaceChildren(...rows);
  $("empty").hidden = state.calls.length > 0;
  $("calls").hidden = state.calls.length === 0;
  renderFilters();
}

function renderFilters() {
  const counts = {};
  for (const c of state.calls) counts[c.provider || "?"] = (counts[c.provider || "?"] || 0) + 1;
  const chip = (label, value, n) => el("button", { type: "button", class: "chip" + (state.filter === value ? " on" : ""), onclick: () => { state.filter = state.filter === value ? null : value; renderRows(); } },
    label, n !== undefined ? el("span", { class: "n" }, n) : null);
  const chips = [chip("All", null, state.calls.length)];
  for (const [p, n] of Object.entries(counts).sort((a, b) => b[1] - a[1])) chips.push(chip(p, p, n));
  $("filters").replaceChildren(...chips);
}

async function refreshStats() {
  try {
    const s = await api("/api/stats?window=24h");
    $("k-calls").textContent = fmtInt(s.n);
    $("k-tokens").textContent = fmtTok(s.tin + s.tout);
    $("k-tokens-sub").textContent = `${fmtTok(s.tin)} in · ${fmtTok(s.tout)} out`;
    $("k-spend").textContent = fmtUsd(s.usd);
    $("k-shadow").textContent = s.shadow ? `+ ${fmtUsd(s.shadow)} shadow (local)` : "hosted APIs";
    $("k-lat").textContent = s.p50_ms ? `${fmtMs(s.p50_ms)} / ${fmtMs(s.p95_ms)}` : "—";
    $("k-redacted").textContent = fmtInt(s.redacted || 0);
    $("k-blocked").textContent = fmtInt(s.blocked || 0);
    $("rec").classList.remove("off");
    $("rec-label").textContent = state.paused ? "Recording · view paused" : "Recording";
  } catch {
    $("rec").classList.add("off");
    $("rec-label").textContent = "Disconnected";
  }
}

// ---------------------------------------------------------------- live updates
function connectEvents() {
  const es = new EventSource("/api/events");
  es.addEventListener("call", (e) => {
    const c = JSON.parse(e.data);
    if (state.calls.some((x) => x.id === c.id)) return;
    state.calls.unshift(c);
    if (state.calls.length > 2000) state.calls.length = 2000;
    if (!state.paused) renderRows(c.id);
    refreshStats();
  });
  es.onerror = () => { $("rec").classList.add("off"); $("rec-label").textContent = "Reconnecting…"; };
  es.onopen = () => refreshStats();
}

// ---------------------------------------------------------------- detail drawer
async function openDetail(id) {
  state.selected = id;
  document.querySelectorAll("#rows tr").forEach((tr) => tr.classList.toggle("sel", Number(tr.dataset.id) === id));
  const c = await api(`/api/calls/${id}`);
  state.detail = c;
  $("d-title").textContent = `${c.provider || "?"} · ${c.model || c.endpoint || "unknown model"}`;
  $("d-sub").textContent = `${new Date(c.ts * 1000).toLocaleString()} · ${c.method} ${c.host}${c.path} · via ${c.mode}`;
  $("drawer").hidden = false;
  $("scrim").hidden = false;
  renderTab();
}
function closeDetail() {
  $("drawer").hidden = true;
  $("scrim").hidden = true;
  state.selected = null;
  document.querySelectorAll("#rows tr.sel").forEach((tr) => tr.classList.remove("sel"));
}

function withMarks(text) {
  // Highlight [REDACTED:kind] markers without ever interpreting text as HTML.
  const out = [];
  const re = /\[REDACTED:[a-z_]+\]/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(el("span", { class: "redacted-mark" }, m[0]));
    last = m.index + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

function renderTab() {
  const c = state.detail;
  if (!c) return;
  document.querySelectorAll(".d-tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === state.tab));
  const body = $("d-body");
  const kids = [];
  if (state.tab === "conv") {
    if (c.action === "blocked") kids.push(el("div", { class: "callout bad" }, el("b", {}, "Blocked before leaving this Mac. "), (c.reasons || []).join("; ")));
    if (c.action === "redacted") kids.push(el("div", { class: "callout warn" }, el("b", {}, "Redacted. "), (c.reasons || []).join("; "), ". The provider received the masked text below, and only the masked text was stored."));
    if (c.prompt) kids.push(el("div", { class: "msg" }, el("div", { class: "role" }, "Prompt (as forwarded)"), el("div", { class: "text" }, withMarks(c.prompt))));
    else kids.push(el("p", { class: "muted" }, "No prompt text stored (metadata-only capture, or retention expired)."));
    if (c.response) kids.push(el("div", { class: "msg assistant" }, el("div", { class: "role" }, "Response"), el("div", { class: "text" }, withMarks(c.response))));
    if (c.error) kids.push(el("div", { class: "callout bad" }, el("b", {}, "Error. "), c.error));
  } else if (state.tab === "usage") {
    const pairs = [
      ["Input tokens", fmtInt(c.input_tokens)], ["  of which cache read", fmtInt(c.cache_read)], ["  of which cache write", fmtInt(c.cache_write)],
      ["Output tokens", fmtInt(c.output_tokens)], ["  of which reasoning", fmtInt(c.reasoning)], ["Usage source", c.usage_source || "—"],
      ["Cost", c.usd === null ? "unknown model price" : fmtUsd(c.usd)], ["Shadow cost", c.shadow_usd ? fmtUsd(c.shadow_usd) + " (if this local call had used a hosted model)" : "—"],
      ["Time to first token", c.stream ? fmtMs(c.ttft_ms) : "not streamed"], ["Total latency", fmtMs(c.latency_ms)],
      ["Request size", fmtInt(c.req_bytes) + " B"], ["Response size", fmtInt(c.resp_bytes) + " B"],
    ];
    kids.push(el("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])));
    kids.push(el("p", { class: "fine" }, "Prices come from a local, dated table (pricing.yaml) and are approximate."));
  } else if (state.tab === "policy") {
    const f = c.findings || [];
    kids.push(el("div", { class: "callout " + (c.action === "allowed" ? "ok" : c.action === "blocked" ? "bad" : "warn") }, el("b", {}, `Decision: ${c.action}. `), (c.reasons || []).join("; ") || "No policy matched."));
    if (f.length) kids.push(el("dl", { class: "kv" }, f.flatMap((x) => [el("dt", {}, x.kind), el("dd", {}, `${x.count}× · ${x.category}`)])));
    else kids.push(el("p", { class: "muted" }, "No secrets or personal data detected in this request."));
  } else {
    const pairs = [["Mode", c.mode], ["Method", c.method], ["Host", c.host], ["Path", c.path], ["Endpoint", c.endpoint], ["Streamed", c.stream ? "yes" : "no"], ["HTTP status", c.status ?? "—"], ["App (User-Agent)", c.client || "—"], ["Tag", c.tag || "—"], ["Credential fingerprint", c.key_fp ? c.key_fp + "  (SHA-256 prefix; the key itself is never stored)" : "none"]];
    kids.push(el("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, String(v ?? "—"))])));
  }
  body.replaceChildren(...kids);
}

// ---------------------------------------------------------------- insights
async function renderInsights() {
  const d = await api(`/api/insights?window=${state.window}`);
  // spend over time
  const box = $("chart-hour");
  const W = 600, H = 200, P = { l: 44, r: 8, t: 10, b: 22 };
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Spend per hour" });
  const pts = d.by_hour;
  const max = Math.max(0.0001, ...pts.map((p) => p.spend));
  for (let i = 0; i <= 3; i++) {
    const y = P.t + ((H - P.t - P.b) * i) / 3;
    s.append(svg("line", { x1: P.l, x2: W - P.r, y1: y, y2: y, class: "grid" }));
    const lab = svg("text", { x: P.l - 6, y: y + 3, "text-anchor": "end", class: "axis" });
    lab.textContent = fmtUsd(max * (1 - i / 3));
    s.append(lab);
  }
  const slot = (W - P.l - P.r) / Math.max(1, pts.length);
  const bw = pts.length ? Math.min(36, Math.max(2, slot - 3)) : 0;
  pts.forEach((p, i) => {
    const h = ((H - P.t - P.b) * p.spend) / max;
    const x = P.l + i * slot + (slot - bw) / 2;
    const r = svg("rect", { x, y: H - P.b - h, width: bw, height: Math.max(h, p.calls ? 1 : 0), class: "bar", rx: 1.5 });
    const t = svg("title", {});
    t.textContent = `${new Date(p.bucket * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit" })} · ${fmtUsd(p.spend)} · ${p.calls} calls`;
    r.append(t);
    s.append(r);
  });
  if (pts.length) {
    [0, pts.length - 1].forEach((i) => {
      const lab = svg("text", { x: P.l + i * slot + slot / 2, y: H - 6, "text-anchor": "middle", class: "axis" });
      lab.textContent = new Date(pts[i].bucket * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
      s.append(lab);
    });
  }
  box.replaceChildren(pts.length ? s : el("p", { class: "muted" }, "No calls in this window."));
  // clients
  const cmax = Math.max(1, ...d.by_client.map((x) => x.calls));
  $("chart-client").replaceChildren(...(d.by_client.length ? d.by_client.map((x) => {
    const fill = el("div", { class: "fill" });
    fill.style.width = `${(100 * x.calls) / cmax}%`;
    return el("div", { class: "row" }, el("div", { class: "lbl", title: x.client }, x.client), el("div", { class: "track" }, fill), el("div", { class: "v" }, fmtInt(x.calls)));
  }) : [el("p", { class: "muted" }, "No calls in this window.")]));
  // by model
  $("by-model").tBodies[0].replaceChildren(...d.by_model.map((m) => el("tr", {},
    el("td", {}, el("span", { class: "prov", dataset: { p: m.provider || "" } }, el("i"), m.provider || "?")),
    el("td", { class: "mono" }, m.model || "—"), el("td", { class: "num" }, fmtInt(m.calls)),
    el("td", { class: "num" }, fmtTok(m.input_tokens)), el("td", { class: "num" }, fmtTok(m.output_tokens)),
    el("td", { class: "num" }, fmtMs(m.avg_latency_ms)), el("td", { class: "num" }, fmtUsd(m.usd)), el("td", { class: "num muted" }, m.shadow_usd ? fmtUsd(m.shadow_usd) : "—"))));
  const f = Object.entries(d.findings);
  $("findings").replaceChildren(...(f.length ? f.map(([k, n]) => el("span", { class: "chip" }, k, el("span", { class: "n" }, n))) : [el("p", { class: "muted" }, "Nothing sensitive detected in this window.")]));
}

// ---------------------------------------------------------------- setup
async function renderSetup() {
  const s = state.setup || (state.setup = await api("/api/setup"));
  const kv = (pairs) => pairs.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]);
  $("paths").replaceChildren(...kv([
    ["Explicit proxy", `127.0.0.1:${s.ports.proxy}`], ["Gateway (base URL)", `http://127.0.0.1:${s.ports.gateway}/<provider>`],
    ["PAC file", `http://127.0.0.1:${s.ports.ui}/proxy.pac`], ["Parsers loaded", s.parsers.join(", ") || "none"],
    ["Decrypted hosts", s.decrypt_hosts.join(", ")],
  ]));
  $("trust").replaceChildren(...kv([
    ["CA certificate", s.ca.exists ? s.ca.path : "not generated yet"], ["CA key permissions", s.ca.key_mode || "—"],
    ["Body capture", s.capture_bodies], ["Retention", `bodies ${s.retention.bodies_days}d · metadata ${s.retention.metadata_days}d`],
    ["Database", `${s.db.path} (${s.db.mode || "—"})`],
  ]));
  $("never").replaceChildren(...s.never_stored.map((x) => el("li", {}, x)));
  const block = (title, desc, code) => el("div", {}, el("h4", {}, title), el("p", {}, desc), el("pre", {}, code));
  $("howto").replaceChildren(
    block("Base URL (no certificate)", "For SDKs and CLIs that accept a base URL.", `export OPENAI_BASE_URL=http://127.0.0.1:${s.ports.gateway}/openai/v1\nexport ANTHROPIC_BASE_URL=http://127.0.0.1:${s.ports.gateway}/anthropic`),
    block("Terminal (proxy + CA)", "Python, Node, curl, Go in this shell.", 'eval "$(sightline env)"'),
    block("Whole Mac (PAC)", "GUI and Electron apps; only LLM hosts are routed.", "sightline trust\nsightline proxy on"),
  );
  $("policy").textContent = JSON.stringify(s.policy, null, 2);
  $("policy-path").textContent = "policy.yaml in " + s.db.path.replace(/\/[^/]+$/, "");
}

// ---------------------------------------------------------------- routing / boot
function route() {
  const view = (location.hash.replace("#/", "") || "traffic").split("?")[0];
  closeDetail();
  for (const v of ["traffic", "insights", "setup"]) $(`view-${v}`).hidden = v !== view;
  document.querySelectorAll(".tabs a").forEach((a) => a.classList.toggle("on", a.dataset.view === view));
  if (view === "insights") renderInsights().catch(console.error);
  if (view === "setup") renderSetup().catch(console.error);
}

async function boot() {
  document.querySelectorAll(".d-tabs button").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderTab(); }));
  $("d-close").addEventListener("click", closeDetail);
  $("scrim").addEventListener("click", closeDetail);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetail(); });
  $("search").addEventListener("input", (e) => { state.query = e.target.value; renderRows(); });
  $("pause").addEventListener("click", (e) => {
    state.paused = !state.paused;
    e.target.setAttribute("aria-pressed", String(state.paused));
    e.target.textContent = state.paused ? "Resume" : "Pause";
    if (!state.paused) renderRows();
    refreshStats();
  });
  $("window").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    state.window = b.dataset.w;
    $("window").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    renderInsights().catch(console.error);
  }));
  window.addEventListener("hashchange", route);
  try {
    const s = await api("/api/setup");
    state.setup = s;
    $("empty-gateway").textContent = `export OPENAI_BASE_URL=http://127.0.0.1:${s.ports.gateway}/openai/v1`;
  } catch { /* setup panel will retry */ }
  state.calls = await api("/api/calls?limit=500").catch(() => []);
  renderRows();
  refreshStats();
  connectEvents();
  route();
  setInterval(refreshStats, 15000);
}

boot();

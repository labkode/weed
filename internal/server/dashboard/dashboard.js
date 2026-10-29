// The dashboard of weed (/dashboard/): reads /status and /metrics every few seconds
// and shows them, with the last minutes as charts. It changes nothing. What weed says
// becomes text (textContent), never markup.
"use strict";

const INTERVAL = 2000; // ms between two readings
const WINDOW = 10 * 60 * 1000; // ms of history in the charts
const KINDS = ["download", "upload", "tpc_pull", "tpc_push", "other"];
const KIND_NAMES = { download: "downloads", upload: "uploads", tpc_pull: "TPC pulls", tpc_push: "TPC pushes", other: "other" };
const KIND_NAME = { download: "download", upload: "upload", tpc_pull: "TPC pull", tpc_push: "TPC push", other: "other" };
const CLASSES = ["2xx", "3xx", "4xx", "5xx"];
const DELAYS = ["egress account", "egress total", "ingress account", "ingress total"];

const state = {
  paused: false,
  inflight: false,
  timer: 0,
  history: [], // a point per reading: {t, egress, ingress, req, delay, auth (rates), inprog}
  last: null, // the last reading's counters, for rates: {t, pid, c}
  counters: null, // the last counters
  status: null, // the last /status
  samples: [], // the last /metrics
  updated: 0, // when they were read
  error: null,
  sort: { key: "inprog", desc: true },
  filter: "",
  configKey: "",
};

// --- Elements

function setAttrs(e, attrs) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v !== null && v !== undefined && v !== false) e.setAttribute(k, v === true ? "" : String(v));
  }
}

// el(tag, attrs, ...children): an element; strings and numbers become text
function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  setAttrs(e, attrs);
  for (const c of children.flat(Infinity)) {
    if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : String(c));
  }
  return e;
}

function svgEl(tag, attrs, text) {
  const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
  setAttrs(e, attrs);
  if (text !== undefined) e.textContent = text;
  return e;
}

const $ = (id) => document.getElementById(id);

// --- Formats

const PREFIXES = ["", "k", "M", "G", "T", "P"];

// si writes v with an SI prefix (powers of 1000, as weed's rates are written)
function si(v, unit) {
  if (v === null || v === undefined || !Number.isFinite(v)) return "–";
  let x = Math.abs(v);
  let i = 0;
  while (x >= 999.5 && i < PREFIXES.length - 1) {
    x /= 1000;
    i++;
  }
  const digits = x >= 99.5 || (i === 0 && Number.isInteger(x)) ? 0 : x >= 9.95 ? 1 : 2;
  const suffix = PREFIXES[i] + unit;
  return (v < 0 ? "-" : "") + x.toFixed(digits) + (suffix ? " " + suffix : "");
}

const bytesRate = (v) => si(v, "B/s");
const perSecond = (v) => si(v, "/s");
const count = (v) => si(v, "");
const limitRate = (v) => (v > 0 ? bytesRate(v) : "no limit");

function age(ms) {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

const clock = (t) => new Date(t).toLocaleTimeString([], { hour12: false });
const when = (iso) => (iso ? new Date(iso).toLocaleString([], { hour12: false }) : "–");

function total(obj) {
  let sum = null;
  for (const v of Object.values(obj || {})) if (v !== null && v !== undefined) sum = (sum || 0) + v;
  return sum;
}

// --- Readings

// parseMetrics returns the samples of the Prometheus text format: {name, labels, value}
function parseMetrics(text) {
  const samples = [];
  for (const line of text.split("\n")) {
    if (line === "" || line[0] === "#") continue;
    const m = /^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{(.*)\})?\s+(\S+)/.exec(line);
    if (!m) continue;
    const labels = {};
    for (const l of (m[2] || "").matchAll(/([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"/g)) {
      labels[l[1]] = l[2].replace(/\\(.)/g, (_, c) => (c === "n" ? "\n" : c));
    }
    samples.push({ name: m[1], labels, value: parseFloat(m[3]) });
  }
  return samples;
}

// gauge sums the samples of a metric (null if it has none)
function gauge(samples, name, match) {
  let v = null;
  for (const s of samples) if (s.name === name && (!match || match(s.labels))) v = (v || 0) + s.value;
  return v;
}

// counters are what the charts show the rates of
function counters(samples) {
  const c = { egress: 0, ingress: 0, req: {}, delay: {}, auth: {} };
  const add = (m, k, v) => (m[k] = (m[k] || 0) + v);
  for (const { name, labels, value } of samples) {
    switch (name) {
      case "weed_http_response_bytes_total":
        c.egress += value;
        break;
      case "weed_upload_bytes_total":
        c.ingress += value;
        break;
      case "weed_tpc_bytes_total":
        if (labels.mode === "push") c.egress += value;
        if (labels.mode === "pull") c.ingress += value;
        break;
      case "weed_http_requests_total":
        add(c.req, String(labels.code || "?")[0] + "xx", value);
        break;
      case "weed_network_delay_seconds_total":
        add(c.delay, labels.direction + " " + labels.limit, value);
        break;
      case "weed_auth_requests_total":
        add(c.auth, labels.method + " " + labels.result, value);
        break;
    }
  }
  return c;
}

// record adds a point to the history: the rates since the previous reading
function record(t, st, samples) {
  const c = counters(samples);
  const prev = state.last;
  // weed starts its counters again when it restarts: no rate across that
  const dt = prev && prev.pid === st.pid ? (t - prev.t) / 1000 : 0;
  const rate = (now, before) => (dt > 0 && now >= (before || 0) ? (now - (before || 0)) / dt : null);
  const point = { t, egress: null, ingress: null, req: {}, delay: {}, auth: {}, inprog: { ...st.in_progress.total } };
  if (dt > 0) {
    point.egress = rate(c.egress, prev.c.egress);
    point.ingress = rate(c.ingress, prev.c.ingress);
    for (const k of CLASSES) point.req[k] = rate(c.req[k] || 0, prev.c.req[k]);
    for (const k of DELAYS) point.delay[k] = rate(c.delay[k] || 0, prev.c.delay[k]);
    for (const k of Object.keys(c.auth)) point.auth[k] = rate(c.auth[k], prev.c.auth[k]);
  }
  state.last = { t, pid: st.pid, c };
  state.counters = c;
  state.history.push(point);
  while (state.history.length && state.history[0].t < t - WINDOW) state.history.shift();
}

// recent is the average of get over the last n points that have it
function recent(get, n = 5) {
  const h = state.history;
  let sum = 0;
  let k = 0;
  for (let i = h.length - 1; i >= 0 && i >= h.length - n; i--) {
    const v = get(h[i]);
    if (v !== null && v !== undefined) {
      sum += v;
      k++;
    }
  }
  return k ? sum / k : null;
}

// --- Charts

const PAD = { l: 64, r: 10, t: 10, b: 22 };
const HEIGHT = 150;

function niceScale(max, integer) {
  if (!(max > 0)) return integer ? { top: 4, step: 1 } : { top: 1, step: 0.25 };
  const raw = (max * 1.05) / 4;
  const mag = 10 ** Math.floor(Math.log10(raw));
  let step = [1, 2, 2.5, 5, 10].map((f) => f * mag).find((s) => s >= raw);
  if (integer) step = Math.max(1, Math.ceil(step));
  return { top: step * Math.ceil((max * 1.05) / step), step };
}

class Chart {
  // series: [{name, cls, get(point)}]; opts.refs() gives the dashed lines: [{value,
  // label}]; opts.smooth averages each point with the previous ones, over that many
  constructor(title, series, format, opts = {}) {
    this.title = title;
    this.series = series;
    this.format = format;
    this.integer = !!opts.integer;
    this.smooth = opts.smooth || 1;
    this.refs = opts.refs || (() => []);
    this.hover = null;
    this.legend = el("div", { class: "legend" });
    this.plot = el("div", { class: "plot" });
    const note = this.smooth > 1 ? el("span", { class: "note" }, ` ${(this.smooth * INTERVAL) / 1000} s average`) : null;
    this.root = el("figure", { class: "card chart" }, el("h3", {}, title, note), this.legend, this.plot);
    this.plot.addEventListener("pointermove", (e) => this.hoverAt(e.clientX));
    this.plot.addEventListener("pointerleave", () => {
      this.hover = null;
      this.draw();
    });
  }

  hoverAt(clientX) {
    const h = state.history;
    if (!h.length || !this.geom) return;
    const t = this.geom.t0 + ((clientX - this.plot.getBoundingClientRect().left - PAD.l) / this.geom.pw) * WINDOW;
    let best = 0;
    for (let i = 1; i < h.length; i++) if (Math.abs(h[i].t - t) < Math.abs(h[best].t - t)) best = i;
    this.hover = best;
    this.draw();
  }

  // value is what series s shows at point i of the history
  value(s, i) {
    const h = state.history;
    if (this.smooth === 1) return s.get(h[i]);
    let sum = 0;
    let n = 0;
    for (let j = Math.max(0, i - this.smooth + 1); j <= i; j++) {
      const v = s.get(h[j]);
      if (v !== null && v !== undefined) {
        sum += v;
        n++;
      }
    }
    return n && s.get(h[i]) !== null && s.get(h[i]) !== undefined ? sum / n : null;
  }

  draw() {
    const h = state.history;
    const w = Math.max(240, this.plot.clientWidth);
    const pw = w - PAD.l - PAD.r;
    const ph = HEIGHT - PAD.t - PAD.b;
    const t0 = (h.length ? h[h.length - 1].t : Date.now()) - WINDOW;
    const refs = this.refs();
    let max = 0;
    for (const s of this.series) for (let i = 0; i < h.length; i++) max = Math.max(max, this.value(s, i) || 0);
    for (const r of refs) max = Math.max(max, r.value);
    const { top, step } = niceScale(max, this.integer);
    const x = (t) => PAD.l + ((t - t0) / WINDOW) * pw;
    const y = (v) => PAD.t + (1 - v / top) * ph;
    this.geom = { t0, pw };

    const svg = svgEl("svg", { width: w, height: HEIGHT, viewBox: `0 0 ${w} ${HEIGHT}`, role: "img", "aria-label": this.title });
    for (let v = 0; v <= top + step / 2; v += step) {
      svg.append(svgEl("line", { class: "grid", x1: PAD.l, x2: w - PAD.r, y1: y(v), y2: y(v) }));
      svg.append(svgEl("text", { x: PAD.l - 8, y: y(v) + 4, "text-anchor": "end" }, this.format(v)));
    }
    for (const [f, label, anchor] of [[0, "−10 min", "start"], [0.5, "−5 min", "middle"], [1, "now", "end"]]) {
      svg.append(svgEl("text", { x: PAD.l + f * pw, y: HEIGHT - 4, "text-anchor": anchor }, label));
    }
    for (const r of refs) svg.append(svgEl("line", { class: "ref", x1: PAD.l, x2: w - PAD.r, y1: y(r.value), y2: y(r.value) }));
    for (const s of this.series) {
      let d = "";
      let pen = false;
      for (let i = 0; i < h.length; i++) {
        const p = h[i];
        const v = this.value(s, i);
        if (v === null || v === undefined || p.t < t0) {
          pen = false;
          continue;
        }
        d += `${pen ? "L" : "M"}${x(p.t).toFixed(1)} ${y(v).toFixed(1)}`;
        pen = true;
      }
      if (d) svg.append(svgEl("path", { class: s.cls, d }));
    }
    // over the lines, which their outline hides
    for (const r of refs) svg.append(svgEl("text", { class: "reflabel", x: w - PAD.r, y: y(r.value) - 4, "text-anchor": "end" }, r.label));
    const hovered = this.hover !== null && h[this.hover] ? h[this.hover] : null;
    if (hovered) svg.append(svgEl("line", { class: "cursor", x1: x(hovered.t), x2: x(hovered.t), y1: PAD.t, y2: PAD.t + ph }));
    this.plot.replaceChildren(svg);

    const at = hovered ? this.hover : h.length - 1;
    this.legend.replaceChildren(
      ...this.series.map((s) => el("span", {}, el("span", { class: "sw " + s.cls }), s.name + " ", el("b", {}, at >= 0 ? this.format(this.value(s, at)) : "–"))),
      el("span", { class: "when" }, hovered ? clock(hovered.t) : "now"),
    );
  }
}

// weed counts the bytes of a transfer when it ends: the charts of rates average them
const charts = [
  new Chart(
    "Throughput",
    [
      { name: "egress", cls: "s1", get: (p) => p.egress },
      { name: "ingress", cls: "s2", get: (p) => p.ingress },
    ],
    bytesRate,
    {
      refs: () => {
        const n = state.status && state.status.network;
        const refs = [];
        if (n && n.egress_rate > 0) refs.push({ value: n.egress_rate, label: "egress limit " + bytesRate(n.egress_rate) });
        if (n && n.ingress_rate > 0) refs.push({ value: n.ingress_rate, label: "ingress limit " + bytesRate(n.ingress_rate) });
        return refs;
      },
      smooth: 5,
    },
  ),
  new Chart(
    "Requests per second, by status",
    CLASSES.map((k, i) => ({ name: k, cls: ["s3", "s6", "s2", "s7"][i], get: (p) => p.req[k] })),
    perSecond,
    { smooth: 5 },
  ),
  new Chart(
    "Requests in progress",
    KINDS.map((k, i) => ({ name: KIND_NAMES[k], cls: "s" + (i + 1), get: (p) => p.inprog[k] ?? null })),
    count,
    { integer: true },
  ),
  new Chart(
    "Transfers held back by rate limits, on average",
    DELAYS.map((k, i) => ({ name: k.replace(" ", ", "), cls: ["s1", "s5", "s2", "s4"][i], get: (p) => p.delay[k] })),
    count,
    { smooth: 5 },
  ),
];

// --- Sections

function tile(label, value, sub, level) {
  return el("div", { class: "tile" + (level ? " " + level : "") }, el("div", { class: "label" }, label), el("div", { class: "value" }, value), el("div", { class: "sub" }, sub));
}

function renderHeader(st) {
  $("host").textContent = " " + location.host;
  $("facts").replaceChildren(
    el("span", {}, "version ", el("b", {}, st.version.version)),
    el("span", {}, "up ", el("b", {}, st.uptime)),
    el("span", {}, "since ", el("b", {}, when(st.started))),
    el("span", {}, "pid ", el("b", {}, st.pid)),
  );
}

function renderAlerts() {
  const st = state.status;
  const alerts = [];
  if (state.error) {
    alerts.push(["err", `Cannot read weed: ${state.error}.` + (state.updated ? ` What follows is from ${age(Date.now() - state.updated)} ago.` : "")]);
  }
  if (st) {
    for (const [reason, why] of Object.entries(st.restart_pending || {})) alerts.push(["warn", `Restart pending (${reason}): ${why}`]);
    if (st.reload && !st.reload.successful) {
      alerts.push(["warn", `The last reload (${when(st.reload.last)}) could not read every file, which kept their previous contents: see weed's log. The last complete one: ${when(st.reload.last_success)}.`]);
    }
    const blocked = st.workers.reduce((s, w) => s + w.blocked_threads, 0);
    if (blocked) alerts.push(["err", `${blocked} threads of workers wait for storage that does not answer: their requests do not end.`]);
    if (st.banned_users) alerts.push(["info", `${st.banned_users} banned users: weed utils bans lists them.`]);
    const cert = gauge(state.samples, "weed_tls_certificate_expiry_timestamp_seconds");
    if (cert) {
      const left = cert * 1000 - Date.now();
      if (left < 0) alerts.push(["err", "The TLS certificate has expired."]);
      else if (left < 14 * 86400e3) alerts.push(["warn", `The TLS certificate expires in ${age(left)}.`]);
    }
    const crl = gauge(state.samples, "weed_crl_expiry_timestamp_seconds");
    if (crl) {
      const left = crl * 1000 - Date.now();
      if (left < 0) alerts.push(["err", "A CA has no current CRL: is fetch-crl running?"]);
      else if (left < 6 * 3600e3) alerts.push(["warn", `CRLs run out in ${age(left)}: is fetch-crl running?`]);
    }
  }
  $("alerts").replaceChildren(...alerts.map(([level, text]) => el("div", { class: "alert " + level }, text)));
}

function renderTiles(st) {
  const n = st.network;
  const inprog = st.in_progress.total;
  const accounts = new Set(st.workers.map((w) => w.account)).size;
  const blocked = st.workers.reduce((s, w) => s + w.blocked_threads, 0);
  const pull = gauge(state.samples, "weed_tpc_active_transfers", (l) => l.mode === "pull") || 0;
  const push = gauge(state.samples, "weed_tpc_active_transfers", (l) => l.mode === "push") || 0;
  const errors = recent((p) => p.req["5xx"]);
  const tiles = [
    tile("Egress", bytesRate(recent((p) => p.egress)), n && n.egress_rate > 0 ? "of " + bytesRate(n.egress_rate) : "no total limit"),
    tile("Ingress", bytesRate(recent((p) => p.ingress)), n && n.ingress_rate > 0 ? "of " + bytesRate(n.ingress_rate) : "no total limit"),
    tile("Requests", perSecond(recent((p) => total(p.req))), `4xx ${perSecond(recent((p) => p.req["4xx"]))} · 5xx ${perSecond(errors)}`, errors > 0 ? "warn" : null),
    tile("In progress", count(total(inprog)), `${inprog.download || 0} down · ${inprog.upload || 0} up · ${(inprog.tpc_pull || 0) + (inprog.tpc_push || 0)} TPC`),
  ];
  if (n) {
    const held = n.accounts.reduce((s, a) => s + a.held_egress + a.held_ingress, 0);
    tiles.push(tile("Held by rates", count(held), `${count(recent((p) => total(p.delay)))} on average`, held ? "warn" : null));
  }
  tiles.push(
    tile("Workers", count(st.workers.length), `${accounts} accounts · ${blocked} blocked threads`, blocked ? "err" : null),
    tile("Third-party copies", count(pull + push), `${pull} pulling · ${push} pushing`),
    tile("Banned users", count(st.banned_users), "weed utils bans lists them"),
  );
  $("tiles").replaceChildren(...tiles);
}

// table renders rows with columns [{key, label, num, value(row), render(row)}]; with
// sort, the columns that have a value sort the rows when clicked
function table(columns, rows, sort) {
  const head = columns.map((c) => {
    const th = el("th", { class: c.num ? "num" : null, scope: "col" });
    if (sort && c.value) {
      const b = el("button", { type: "button" }, c.label);
      if (sort.key === c.key) th.setAttribute("aria-sort", sort.desc ? "descending" : "ascending");
      b.addEventListener("click", () => {
        state.sort = { key: c.key, desc: sort.key === c.key ? !sort.desc : c.key !== "account" };
        renderAccounts();
      });
      th.append(b);
    } else {
      th.append(c.label);
    }
    return th;
  });
  const body = rows.map((r) => el("tr", {}, columns.map((c) => el("td", { class: c.num ? "num" : null }, c.render(r)))));
  return el("table", {}, el("thead", {}, el("tr", {}, head)), el("tbody", {}, body));
}

const ACCOUNT_COLUMNS = [
  { key: "account", label: "Account", value: (r) => r.account, render: (r) => r.account },
  {
    key: "workers", label: "Workers", num: true,
    value: (r) => r.workers + r.retired,
    render: (r) => [String(r.workers), r.retired ? el("span", { class: "muted" }, ` + ${r.retired} retired`) : null],
  },
  { key: "inprog", label: "In progress", num: true, value: (r) => r.inprog, render: (r) => r.inprog },
  {
    key: "kinds", label: "Of which",
    render: (r) => KINDS.filter((k) => r.kinds[k]).map((k) => `${r.kinds[k]} ${(r.kinds[k] === 1 ? KIND_NAME : KIND_NAMES)[k]}`).join(", ") || "–",
  },
  {
    key: "held", label: "Held out / in", num: true, network: true,
    value: (r) => (r.limits ? r.limits.held_egress + r.limits.held_ingress : 0),
    render: (r) => (r.limits ? el("span", { class: r.limits.held_egress + r.limits.held_ingress ? "held" : null }, `${r.limits.held_egress} / ${r.limits.held_ingress}`) : "–"),
  },
  {
    key: "egress", label: "Egress rate", num: true, network: true,
    value: (r) => (r.limits && r.limits.egress_rate > 0 ? r.limits.egress_rate : Infinity),
    render: (r) => (r.limits ? limitRate(r.limits.egress_rate) : "–"),
  },
  {
    key: "ingress", label: "Ingress rate", num: true, network: true,
    value: (r) => (r.limits && r.limits.ingress_rate > 0 ? r.limits.ingress_rate : Infinity),
    render: (r) => (r.limits ? limitRate(r.limits.ingress_rate) : "–"),
  },
  {
    key: "weight", label: "Weight", num: true, network: true,
    value: (r) => (r.limits ? r.limits.weight : 0),
    render: (r) => (r.limits ? r.limits.weight : "–"),
  },
  {
    key: "blocked", label: "Blocked threads", num: true,
    value: (r) => r.blocked,
    render: (r) => (r.blocked ? el("span", { class: "bad" }, r.blocked) : "0"),
  },
];

// accountRows joins, by account, its workers, its requests in progress and its rates
function accountRows(st) {
  const rows = new Map();
  const row = (name) => {
    if (!rows.has(name)) rows.set(name, { account: name, workers: 0, retired: 0, blocked: 0, kinds: {}, inprog: 0, limits: null });
    return rows.get(name);
  };
  for (const w of st.workers) {
    const r = row(w.account);
    if (w.retired) r.retired++;
    else r.workers++;
    r.blocked += w.blocked_threads;
  }
  for (const [user, kinds] of Object.entries(st.in_progress.by_user || {})) {
    const r = row(user);
    r.kinds = kinds;
    r.inprog = total(kinds) || 0;
  }
  for (const a of (st.network && st.network.accounts) || []) row(a.account).limits = a;
  return [...rows.values()];
}

function renderAccounts() {
  const st = state.status;
  if (!st) return;
  const columns = ACCOUNT_COLUMNS.filter((c) => !c.network || st.network);
  const sortBy = columns.find((c) => c.key === state.sort.key && c.value) || columns[0];
  const filter = state.filter.toLowerCase();
  const rows = accountRows(st).filter((r) => r.account.toLowerCase().includes(filter));
  rows.sort((a, b) => {
    const va = sortBy.value(a);
    const vb = sortBy.value(b);
    const order = typeof va === "string" ? va.localeCompare(vb) : va === vb ? 0 : va < vb ? -1 : 1;
    return (state.sort.desc ? -order : order) || a.account.localeCompare(b.account);
  });
  $("accounts").replaceChildren(rows.length ? table(columns, rows, state.sort) : el("div", { class: "empty" }, filter ? "No account matches." : "No account has workers or requests in progress."));
}

function renderWorkers(st) {
  const workers = [...st.workers].sort((a, b) => a.account.localeCompare(b.account) || a.pid - b.pid);
  $("workers-note").textContent = "a process per Unix account, which accesses its files";
  const columns = [
    { label: "Account", render: (w) => w.account },
    { label: "PID", num: true, render: (w) => w.pid },
    { label: "UID", num: true, render: (w) => w.uid },
    { label: "Running for", num: true, render: (w) => age(Date.now() - Date.parse(w.started)) },
    { label: "Requests", num: true, render: (w) => w.requests },
    { label: "State", render: (w) => (w.retired ? el("span", { class: "muted" }, "retired: finishing its requests") : "serving") },
    { label: "Blocked threads", num: true, render: (w) => (w.blocked_threads ? el("span", { class: "bad" }, w.blocked_threads) : "0") },
  ];
  $("workers").replaceChildren(workers.length ? table(columns, workers) : el("div", { class: "empty" }, "No worker runs: they start with the first request of their account."));
}

function renderAuth() {
  const c = state.counters;
  const keys = c ? Object.keys(c.auth).sort() : [];
  const rows = keys.map((k) => {
    const [method, result] = k.split(" ");
    return { method, result, total: c.auth[k], rate: recent((p) => p.auth[k]) };
  });
  const columns = [
    { label: "Method", render: (r) => r.method },
    { label: "Result", render: (r) => (r.result === "success" ? r.result : el("span", { class: "held" }, r.result)) },
    { label: "Since weed started", num: true, render: (r) => count(r.total) },
    { label: "Now", num: true, render: (r) => perSecond(r.rate) },
  ];
  $("auth").replaceChildren(rows.length ? table(columns, rows) : el("div", { class: "empty" }, "No authenticated request yet."));
}

function renderConfig(st) {
  const key = JSON.stringify([st.version, st.config, st.pid]);
  if (key === state.configKey) return;
  state.configKey = key;
  const kv = (rows) => el("table", {}, el("tbody", {}, rows.map(([k, v]) => el("tr", {}, el("td", {}, k), el("td", {}, v)))));
  const value = (v) => (v !== null && typeof v === "object" ? JSON.stringify(v) : String(v));
  const v = st.version;
  const blocks = [
    el("div", {}, el("h4", {}, "build"), kv([
      ["version", v.version], ["revision", v.revision + (v.modified ? " (modified)" : "")], ["built", when(v.time)],
      ["go", v.go], ["platform", v.platform], ["build ID", v.build],
    ])),
    el("div", {}, el("h4", {}, "configuration file"), kv([
      ["file", st.config.file || "none"], ["sha256", st.config.sha256 || "–"], ["started", when(st.started)], ["pid", st.pid],
    ])),
  ];
  for (const section of Object.keys(st.config.settings).sort()) {
    const settings = st.config.settings[section];
    blocks.push(el("div", {}, el("h4", {}, section), kv(Object.keys(settings).sort().map((k) => [k, value(settings[k])]))));
  }
  $("config").replaceChildren(el("div", { class: "config" }, blocks));
}

function render() {
  renderAlerts();
  const st = state.status;
  if (st) {
    renderHeader(st);
    renderTiles(st);
    renderAccounts();
    renderWorkers(st);
    renderAuth();
    renderConfig(st);
  }
  for (const c of charts) c.draw();
  updated();
}

function updated() {
  let text = "connecting…";
  if (state.paused) text = "paused";
  else if (state.error) text = "not updating";
  else if (state.updated) text = `updated ${age(Date.now() - state.updated)} ago`;
  $("updated").textContent = text;
}

// --- Polling

async function get(url, body) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${url.slice(2)}: ${r.status} ${r.statusText}`);
  return body(r);
}

async function poll() {
  clearTimeout(state.timer);
  if (state.inflight) return;
  if (state.paused || document.hidden) {
    state.last = null; // no rate across the gap
    return;
  }
  state.inflight = true;
  try {
    const [st, text] = await Promise.all([get("../status", (r) => r.json()), get("../metrics", (r) => r.text())]);
    const t = Date.now();
    state.samples = parseMetrics(text);
    record(t, st, state.samples);
    state.status = st;
    state.updated = t;
    state.error = null;
  } catch (e) {
    state.error = e.message || String(e);
    state.last = null;
  } finally {
    state.inflight = false;
  }
  render();
  state.timer = setTimeout(poll, INTERVAL);
}

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) poll();
});
window.addEventListener("resize", () => charts.forEach((c) => c.draw()));
$("pause").addEventListener("click", (e) => {
  state.paused = !state.paused;
  e.currentTarget.textContent = state.paused ? "Resume" : "Pause";
  e.currentTarget.setAttribute("aria-pressed", String(state.paused));
  if (state.paused) state.last = null;
  updated();
  poll();
});
$("filter").addEventListener("input", (e) => {
  state.filter = e.target.value;
  renderAccounts();
});
$("charts").append(...charts.map((c) => c.root));
setInterval(updated, 1000);
poll();

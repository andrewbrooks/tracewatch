/* ===== util: DOM builders (text only, never parsed as markup), formatting, icons, data indexes ===== */
const DATA = JSON.parse(document.getElementById('tw-data').textContent);
const SVGNS = 'http://www.w3.org/2000/svg';
const $ = (sel, root) => (root || document).querySelector(sel);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

/* h(tag, attrs, ...children): attrs are set with setAttribute / property assignment; strings become TEXT nodes.
   Nothing from the recorded data is ever parsed as markup. */
function h(tag, attrs, ...kids) { return build(document.createElement(tag), attrs, kids); }
function s(tag, attrs, ...kids) { return build(document.createElementNS(SVGNS, tag), attrs, kids); }
function build(el, attrs, kids) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.setAttribute('class', v);
    else if (k === 'style' && typeof v === 'object') { for (const [sk, sv] of Object.entries(v)) { if (sk.startsWith('--')) el.style.setProperty(sk, sv); else el.style[sk] = sv; } }
    else el.setAttribute(k, v === true ? '' : v);
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const c of kids.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

/* ---------- formatting ---------- */
const fmtN = n => (n === null || n === undefined) ? '—' : Number(n).toLocaleString('en-US');
function fmtT(ns) {                       // time since T0
  if (ns === null || ns === undefined) return '—';
  const a = Math.abs(ns);
  if (a < 1e6) return (ns / 1e3).toFixed(0) + ' µs';
  if (a < 1e9) return (ns / 1e6).toFixed(a < 1e7 ? 1 : 0) + ' ms';
  if (a < 60e9) return (ns / 1e9).toFixed(2) + ' s';
  return Math.floor(ns / 60e9) + 'm ' + ((ns % 60e9) / 1e9).toFixed(0) + 's';
}
const fmtAt = ns => (ns === null || ns === undefined) ? '—' : '+' + (ns / 1e9).toFixed(3) + 's';
function fmtB(n) {
  if (n === null || n === undefined) return '—';
  for (const [u, d] of [['GB', 2 ** 30], ['MB', 2 ** 20], ['KB', 2 ** 10]]) if (n >= d) return (n / d).toFixed(n >= 10 * d ? 0 : 1) + ' ' + u;
  return n + ' B';
}
const short = (t, n) => { t = String(t ?? ''); return t.length > n ? t.slice(0, n - 1) + '…' : t; };
const oneLine = t => String(t ?? '').replace(/\s*\n\s*/g, ' ⏎ ');
function fmtWall(ns) {
  if (!ns) return '—';
  const d = new Date(ns / 1e6);
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
function niceTicks(max, n) {
  if (max <= 0) return [0, 1];
  const raw = max / n, mag = 10 ** Math.floor(Math.log10(raw)), r = raw / mag;
  const step = (r <= 1 ? 1 : r <= 2 ? 2 : r <= 5 ? 5 : 10) * mag, out = [];
  for (let v = 0; v <= max + step * 0.999; v += step) out.push(Math.round(v * 1e6) / 1e6);
  return out;
}
function timeTicks(d0, d1, n) {            // nice ticks in ns for a time axis
  const span = Math.max(1, d1 - d0), units = [1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 2e9, 5e9, 1e10, 3e10, 6e10, 3e11, 6e11];
  let step = units.find(u => span / u <= n) || units[units.length - 1];
  const out = []; for (let v = Math.ceil(d0 / step) * step; v <= d1; v += step) out.push(v);
  return out;
}
function tickLabel(ns, span) {
  if (ns === 0) return '0';
  if (span < 2e6) return (ns / 1e3).toFixed(0) + 'µs';
  if (ns < 1e9) return (ns / 1e6).toFixed(0) + 'ms';
  return (ns / 1e9).toFixed(span < 20e9 ? 1 : 0) + 's';
}

/* ---------- semantic tables ---------- */
const KINDS = [
  { id: 'exec', label: 'Process', css: '--k-exec', shape: 'circle' },
  { id: 'http', label: 'HTTP', css: '--k-http', shape: 'diamond' },
  { id: 'net', label: 'Network', css: '--k-net', shape: 'triangle' },
  { id: 'file', label: 'File', css: '--k-file', shape: 'square' },
  { id: 'dns', label: 'DNS', css: '--k-dns', shape: 'plus' },
  { id: 'ws', label: 'WebSocket', css: '--k-ws', shape: 'ring' },
];
const rootStyle = getComputedStyle(document.documentElement);
const cssv = n => rootStyle.getPropertyValue(n).trim();
const KC = {};
const GROUP = { exec: 'exec', exit: 'exec', tcp: 'net', udp: 'net', unix: 'net', http: 'http', ws: 'ws', dns: 'dns', file: 'file' };
const groupOf = e => GROUP[e.kind] || 'exec';
const SEV = { high: { label: 'High', css: '--critical', rank: 3 }, medium: { label: 'Medium', css: '--serious', rank: 2 },
  low: { label: 'Low', css: '--warning', rank: 1 }, info: { label: 'Info', css: '--sev-info', rank: 0 } };
const SEVC = {};
function readColors() { for (const k of KINDS) KC[k.id] = cssv(k.css); for (const [k, v] of Object.entries(SEV)) SEVC[k] = cssv(v.css); }
const ink = a => 'rgba(' + cssv('--ink-rgb') + ',' + a + ')';   // translucent wash that adapts to the theme

/* ---------- theme: auto follows the OS, light/dark override and persist ---------- */
const THEME_KEY = 'tw-theme';
let themePref = 'auto';
try { themePref = localStorage.getItem(THEME_KEY) || 'auto'; } catch (e) { /* file:// storage can be blocked */ }
if (!['auto', 'light', 'dark'].includes(themePref)) themePref = 'auto';
const lightMQ = matchMedia('(prefers-color-scheme: light)');
function applyTheme() { document.documentElement.dataset.theme = themePref === 'auto' ? (lightMQ.matches ? 'light' : 'dark') : themePref; readColors(); }
applyTheme();

function shapePath(shape, x, y, r) {
  switch (shape) {
    case 'diamond': return `M${x},${y - r * 1.25}L${x + r * 1.25},${y}L${x},${y + r * 1.25}L${x - r * 1.25},${y}Z`;
    case 'triangle': return `M${x},${y - r * 1.25}L${x + r * 1.15},${y + r * .95}L${x - r * 1.15},${y + r * .95}Z`;
    case 'square': return `M${x - r},${y - r}h${2 * r}v${2 * r}h${-2 * r}Z`;
    case 'plus': { const a = r * .5; return `M${x - a},${y - r * 1.1}h${2 * a}v${r * 1.1 - a}h${r * 1.1 - a}v${2 * a}h${-(r * 1.1 - a)}v${r * 1.1 - a}h${-2 * a}v${-(r * 1.1 - a)}h${-(r * 1.1 - a)}v${-2 * a}h${r * 1.1 - a}Z`; }
    default: return `M${x - r},${y}a${r},${r} 0 1,0 ${2 * r},0a${r},${r} 0 1,0 ${-2 * r},0`;
  }
}
function marker(shape, x, y, r, color, ring) {   // 2px surface ring, filled shape; "ring" = hollow
  const hollow = shape === 'ring';
  return s('path', { d: shapePath(hollow ? 'circle' : shape, x, y, r), fill: hollow ? 'none' : color, stroke: hollow ? color : cssv('--surface'),
    'stroke-width': hollow ? 2 : 2, 'paint-order': 'stroke' });
}

/* ---------- icons (24px, stroke) ---------- */
const ICONS = {
  overview: 'M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z',
  tree: 'M5 4h5v4H5zM14 9h5v4h-5zM14 16h5v4h-5zM10 6h2a2 2 0 0 1 2 2v3M12 8v10a2 2 0 0 0 2 2',
  timeline: 'M3 6h9M7 12h12M5 18h8M3 3v18',
  network: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
  http: 'M7 7l-4 4 4 4M3 11h13M17 17l4-4-4-4M21 13H8',
  dns: 'M4 5h16v5H4zM4 14h16v5H4zM8 7.5h.01M8 16.5h.01',
  commands: 'M4 5h16v14H4zM7 9l3 3-3 3M12 15h5',
  files: 'M6 3h8l4 4v14H6zM14 3v5h5',
  findings: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM12 8v5M12 16h.01',
  events: 'M4 6h16M4 12h16M4 18h10',
  run: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v6M12 7.5h.01',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4',
  download: 'M12 4v11M7 11l5 5 5-5M5 20h14',
  close: 'M6 6l12 12M18 6L6 18',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z',
  auto: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 3v18M12 3a9 9 0 0 1 0 18',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  warn: 'M12 3l10 18H2zM12 10v5M12 18h.01',
  x: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM9 9l6 6M15 9l-6 6',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 11v5M12 8h.01',
  fit: 'M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5',
  expand: 'M5 9l7 7 7-7', collapse: 'M5 15l7-7 7 7', plus: 'M12 5v14M5 12h14',
};
function icon(name, size, extra) {
  const svg = s('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.7, 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    width: size || 20, height: size || 20, 'aria-hidden': 'true', class: extra || '' }, s('path', { d: ICONS[name] || ICONS.info }));
  return svg;
}
const SEVICON = { high: 'x', medium: 'warn', low: 'warn', info: 'info' };
function sevPill(sev, text) {
  return h('span', { class: 'sev sev-' + sev }, icon(SEVICON[sev], 12), text || SEV[sev].label);
}

/* ---------- data indexes ---------- */
const P = new Map(DATA.processes.map(p => [p.id, p]));
const E = new Map(DATA.events.map(e => [e.id, e]));
const HX = new Map(DATA.http.map(x => [x.id, x]));
const FD = new Map(DATA.findings.map(f => [f.id, f]));
const evByProc = new Map(); for (const e of DATA.events) { if (!e.proc) continue; if (!evByProc.has(e.proc)) evByProc.set(e.proc, []); evByProc.get(e.proc).push(e); }
const DUR = Math.max(DATA.run.duration_ns || 0, ...DATA.events.map(e => e.t), 1);
function chainOf(pid) { const out = []; let p = P.get(pid); while (p) { out.unshift(p); p = p.parent ? P.get(p.parent) : null; } return out; }
function descendants(pid) { const out = []; const st = [pid]; while (st.length) { const p = P.get(st.pop()); if (!p) continue; for (const c of p.children) { out.push(c); st.push(c); } } return out; }
const pLabel = id => { const p = P.get(id); return p ? p.name + ' · ' + p.pid : 'unattributed'; };

/* ---------- state, tooltip, copy ---------- */
const S = { tab: 'overview', range: null, sel: null, q: '', kinds: Object.fromEntries(KINDS.map(k => [k.id, true])), probes: false, listeners: [] };
function onState(fn) { S.listeners.push(fn); }
function setState(patch) { Object.assign(S, patch); for (const fn of S.listeners) fn(); }
const inRange = t => !S.range || (t >= S.range[0] && t <= S.range[1]);
const qmatch = (...fields) => { if (!S.q) return true; const q = S.q.toLowerCase(); return fields.some(f => String(f ?? '').toLowerCase().includes(q)); };

const tipEl = h('div', { class: 'tip', role: 'tooltip' });
function showTip(x, y, nodes) {
  clear(tipEl); add(tipEl, [nodes]); tipEl.style.display = 'block';
  const w = tipEl.offsetWidth, hh = tipEl.offsetHeight;
  tipEl.style.left = Math.min(x + 14, innerWidth - w - 8) + 'px'; tipEl.style.top = Math.min(y + 14, innerHeight - hh - 8) + 'px';
}
function hideTip() { tipEl.style.display = 'none'; }
function copyBtn(text) {
  return h('button', { class: 'copy', type: 'button', onclick: ev => { ev.stopPropagation(); (navigator.clipboard?.writeText(text) || Promise.reject()).then(() => flash(ev.target, 'copied'), () => flash(ev.target, 'press ⌘/Ctrl+C')); } }, 'copy');
}
function flash(btn, text) { const o = btn.textContent; btn.textContent = text; setTimeout(() => { btn.textContent = o; }, 1100); }

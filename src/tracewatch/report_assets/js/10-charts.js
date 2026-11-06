/* ===== charts: activity (stacked columns + brush), ranked bars, coverage strip, table-view twin ===== */

/* A chart card with the accessibility twin: every chart can be shown as a table. */
function chartCard(title, build, buildTable, opts) {
  opts = opts || {};
  let asTable = false;
  const body = h('div', { class: 'card-b' });
  const toggle = h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', title: 'Show the same data as a table', onclick: () => { asTable = !asTable; toggle.setAttribute('aria-pressed', String(asTable)); draw(); } }, 'Table view');
  const card = h('section', { class: 'card ' + (opts.cls || '') }, h('div', { class: 'card-h' }, h('h3', null, title), opts.count !== undefined ? h('span', { class: 'cnt' }, opts.count) : null, h('span', { class: 'sp' }), opts.extra || null, toggle), body);
  function draw() { clear(body); body.appendChild(asTable ? buildTable() : build(body)); }
  card.redraw = draw;
  draw();
  return card;
}

/* bucketed event counts per kind over [0, DUR] */
function bucketize(events, n) {
  const w = DUR / n, b = Array.from({ length: n }, (_, i) => ({ i, t0: i * w, t1: (i + 1) * w, c: Object.fromEntries(KINDS.map(k => [k.id, 0])) }));
  for (const e of events) { const g = groupOf(e); const i = Math.min(n - 1, Math.max(0, Math.floor(e.t / w))); b[i].c[g]++; }
  return b;
}

function activityChart(opts) {
  opts = opts || {}; const H = opts.height || 190, N = opts.buckets || 56, M = { l: opts.left ?? 38, r: opts.right ?? 10, t: 8, b: opts.noX ? 6 : 22 };
  const wrap = h('div', { style: { position: 'relative' } });
  const legend = h('div', { class: 'legend', style: { marginBottom: '4px' } });
  const holder = h('div', null);
  add(wrap, [legend, holder]);
  let svg;
  function legendDraw(counts) {
    clear(legend);
    for (const k of KINDS) legend.appendChild(h('button', { class: 'lg', type: 'button', 'aria-pressed': String(S.kinds[k.id]), title: 'Show or hide ' + k.label, onclick: () => setState({ kinds: { ...S.kinds, [k.id]: !S.kinds[k.id] } }) },
      s('svg', { width: 11, height: 11, viewBox: '0 0 11 11', 'aria-hidden': 'true' }, marker(k.shape, 5.5, 5.5, 3.6, KC[k.id])), k.label, h('span', { class: 'c num' }, fmtN(counts[k.id]))));
    if (S.range) legend.appendChild(h('button', { class: 'btn', type: 'button', style: { marginLeft: 'auto' }, onclick: () => setState({ range: null }) }, 'Clear time range · ' + fmtAt(S.range[0]) + ' – ' + fmtAt(S.range[1])));
  }
  function draw() {
    if (!DATA.events.length) { clear(legend); clear(holder).appendChild(emptyState('timeline', 'No activity to chart', 'The recorder saw no events for this run.')); return; }
    const W = Math.max(320, wrap.clientWidth || 800), pw = W - M.l - M.r, ph = H - M.t - M.b;
    const buckets = bucketize(DATA.events.filter(e => !(e.kind === 'udp' && e.detail.probe && !S.probes)), N);
    const on = KINDS.filter(k => S.kinds[k.id]);
    const totals = Object.fromEntries(KINDS.map(k => [k.id, buckets.reduce((a, b) => a + b.c[k.id], 0)]));
    legendDraw(totals);
    const maxc = Math.max(1, ...buckets.map(b => on.reduce((a, k) => a + b.c[k.id], 0)));
    const ticks = intTicks(maxc, 4), ymax = ticks[ticks.length - 1] || 1, sy = ph / ymax, bw = pw / N, thick = Math.min(24, bw - 2);
    const x = t => M.l + (t / DUR) * pw;
    svg = s('svg', { class: 'chart', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Activity over time by event kind. Use the table view for the exact numbers.' });
    const ax = s('g', { class: 'axis' });
    for (const t of ticks) { const y = M.t + ph - t * sy; ax.appendChild(s('line', { x1: M.l, x2: W - M.r, y1: y, y2: y, class: 'gridline' })); ax.appendChild(s('text', { x: M.l - 7, y: y + 3.5, 'text-anchor': 'end' }, fmtN(t))); }
    if (!opts.noX) for (const t of timeTicks(0, DUR, Math.max(3, Math.floor(pw / 90)))) { ax.appendChild(s('text', { x: x(t), y: H - 6, 'text-anchor': 'middle' }, tickLabel(t, DUR))); }
    svg.appendChild(ax);
    const bars = s('g'); svg.appendChild(bars);
    const base = M.t + ph;
    for (const b of buckets) {
      let acc = 0, topIdx = -1; on.forEach((k, i) => { if (b.c[k.id]) topIdx = i; });
      on.forEach((k, i) => {
        const n = b.c[k.id]; if (!n) return;
        const bx = M.l + b.i * bw + (bw - thick) / 2, yBot = base - acc * sy - (acc > 0 ? 1 : 0), yTop = base - (acc + n) * sy + (i === topIdx ? 0 : 1);
        const hh = Math.max(2, yBot - yTop), top = i === topIdx, r = top ? Math.min(4, hh / 2, thick / 2) : 0; acc += n;
        // 2px surface gap between stacked segments (1px off each side); only the outermost data-end is rounded, the baseline stays square
        const d = top ? `M${bx},${yTop + hh}V${yTop + r}Q${bx},${yTop} ${bx + r},${yTop}H${bx + thick - r}Q${bx + thick},${yTop} ${bx + thick},${yTop + r}V${yTop + hh}Z` : `M${bx},${yTop}h${thick}v${hh}h${-thick}Z`;
        bars.appendChild(s('path', { d, fill: KC[k.id] }));
      });
    }
    if (DATA.integrity.untrusted_after_mono) {   // the recorder had died: everything right of this line is unverified
      const ux = x(untrustedAt()), nearEdge = ux > W - M.r - 90;
      svg.appendChild(s('rect', { x: ux, y: M.t, width: Math.max(0, W - M.r - ux), height: ph, fill: ink(0.07), 'pointer-events': 'none' }));
      svg.appendChild(s('line', { x1: ux, x2: ux, y1: M.t, y2: M.t + ph, stroke: cssv('--critical'), 'stroke-width': 1.5, 'pointer-events': 'none' }));
      svg.appendChild(s('text', { x: nearEdge ? ux - 6 : ux + 6, y: M.t + 12, 'text-anchor': nearEdge ? 'end' : 'start', fill: cssv('--t-critical'), 'font-size': 10.5, 'font-weight': 700, 'pointer-events': 'none' }, 'UNTRUSTED'));
    }
    // hover layer: crosshair band + tooltip listing every kind at that bucket
    const band = s('rect', { y: M.t, height: ph, width: bw, fill: ink(0.06), display: 'none', 'pointer-events': 'none' });
    const sel = s('rect', { y: M.t, height: ph, class: 'brush-sel', display: S.range ? '' : 'none', 'pointer-events': 'none' });
    if (S.range) { sel.setAttribute('x', x(S.range[0])); sel.setAttribute('width', Math.max(2, x(S.range[1]) - x(S.range[0]))); }
    svg.appendChild(band); svg.appendChild(sel);
    const hit = s('rect', { x: M.l, y: M.t, width: pw, height: ph, fill: 'transparent', style: { cursor: 'crosshair' } });
    let drag = null;
    const bucketAt = ev => { const r = svg.getBoundingClientRect(); const i = Math.max(0, Math.min(N - 1, Math.floor((ev.clientX - r.left - M.l) / bw))); return buckets[i]; };
    const tAt = ev => { const r = svg.getBoundingClientRect(); return Math.max(0, Math.min(DUR, ((ev.clientX - r.left - M.l) / pw) * DUR)); };
    hit.addEventListener('pointermove', ev => {
      const b = bucketAt(ev); band.setAttribute('x', M.l + b.i * bw); band.setAttribute('display', '');
      if (drag) { const a = Math.min(drag, tAt(ev)), z = Math.max(drag, tAt(ev)); sel.setAttribute('display', ''); sel.setAttribute('x', x(a)); sel.setAttribute('width', Math.max(2, x(z) - x(a))); }
      const rows = on.map(k => h('div', { class: 'tk' }, h('span', { class: 'keyln', style: { background: KC[k.id] } }), h('span', { class: 'tv num' }, fmtN(b.c[k.id])), h('span', { class: 'tip-l' }, k.label)));
      showTip(ev.clientX, ev.clientY, [h('div', { class: 'tip-l' }, fmtAt(b.t0) + ' – ' + fmtAt(b.t1)), rows]);
    });
    hit.addEventListener('pointerleave', () => { band.setAttribute('display', 'none'); hideTip(); });
    hit.addEventListener('pointerdown', ev => { hit.setPointerCapture(ev.pointerId); drag = tAt(ev); });
    hit.addEventListener('pointerup', ev => { const a = Math.min(drag, tAt(ev)), z = Math.max(drag, tAt(ev)); drag = null; if (x(z) - x(a) > 4) setState({ range: [a, z] }); else if (S.range) setState({ range: null }); });
    svg.appendChild(hit);
    clear(holder).appendChild(svg);
  }
  wrap.redraw = draw;
  new ResizeObserver(() => { if (wrap.isConnected && wrap.clientWidth) draw(); }).observe(wrap);
  onState(() => { if (wrap.isConnected) draw(); });
  requestAnimationFrame(draw);
  return wrap;
}

/* ===== activity as swim lanes: one row per kind, a mark at each event's exact time, findings along the top.
   Zoomable (buttons, Ctrl+wheel / pinch, "zoom to selection") with a real horizontal scroll bar; the lane labels stay put. ===== */
function activityLanes() {
  const ZMAX = 600, ML = 8, MR = 14;
  const wrap = h('div', { style: { position: 'relative' } }), legend = h('div', { class: 'legend', style: { marginBottom: '4px' } });
  const labels = s('svg', { class: 'lane-labels', 'aria-hidden': 'true' });
  const scroller = h('div', { class: 'lanes-scroll', tabindex: '0', role: 'group', 'aria-label': 'Activity over time. Scroll sideways; Ctrl and the mouse wheel, or the plus and minus keys, zoom.' });
  add(wrap, [legend, h('div', { class: 'lanes' }, labels, scroller)]);
  let zoom = 1, geom = { pw0: 600 };
  const events = () => DATA.events.filter(e => !(e.kind === 'udp' && e.detail.probe && !S.probes));
  const clampZ = z => Math.min(ZMAX, Math.max(1, z));
  function zoomTo(z, anchorX) {   // keep the moment under `anchorX` (px inside the scroller) where it is
    z = clampZ(z); if (z === zoom) return;
    const tA = ((scroller.scrollLeft + anchorX - ML) / (geom.pw0 * zoom)) * DUR;
    zoom = z; draw(); scroller.scrollLeft = ML + (tA / DUR) * geom.pw0 * zoom - anchorX;
  }
  const centre = () => scroller.clientWidth / 2;
  const tickText = (t, step) => t === 0 ? '0' : step >= 1e6 ? tickLabel(t, DUR) : (t < 1e6 ? (t / 1e3).toFixed(0) + 'µs' : (t / 1e6).toFixed(step >= 1e5 ? 1 : 2) + 'ms');
  function draw() {
    if (!DATA.events.length) { clear(legend); clear(scroller).appendChild(emptyState('timeline', 'No activity to chart', 'The recorder saw no events for this run.')); labels.style.display = 'none'; return; }
    const evs = events(), byKind = Object.fromEntries(KINDS.map(k => [k.id, []]));
    for (const e of evs) byKind[groupOf(e)].push(e);
    const z = PRINTING ? 1 : zoom;
    clear(legend);
    for (const k of KINDS) legend.appendChild(h('button', { class: 'lg', type: 'button', 'aria-pressed': String(S.kinds[k.id]), title: 'Show or hide ' + k.label, onclick: () => setState({ kinds: { ...S.kinds, [k.id]: !S.kinds[k.id] } }) },
      s('svg', { width: 11, height: 11, viewBox: '0 0 11 11', 'aria-hidden': 'true' }, marker(k.shape, 5.5, 5.5, 3.6, KC[k.id])), k.label, h('span', { class: 'c num' }, fmtN(byKind[k.id].length))));
    const zb = h('span', { class: 'zoomctl', role: 'group', 'aria-label': 'Zoom the activity chart' },
      h('button', { class: 'btn', type: 'button', 'aria-label': 'Zoom out', title: 'Zoom out', disabled: zoom <= 1, onclick: () => zoomTo(zoom / 1.6, centre()) }, '−'),
      h('span', { class: 'zl', title: 'Current zoom' }, zoom < 10 ? '×' + zoom.toFixed(1) : '×' + Math.round(zoom)),
      h('button', { class: 'btn', type: 'button', 'aria-label': 'Zoom in', title: 'Zoom in (Ctrl + wheel)', disabled: zoom >= ZMAX, onclick: () => zoomTo(zoom * 1.6, centre()) }, '+'),
      S.range ? h('button', { class: 'btn', type: 'button', title: 'Zoom to the selected time range', onclick: () => { const span = Math.max(1, S.range[1] - S.range[0]); zoom = clampZ(DUR / (span * 1.1)); draw(); scroller.scrollLeft = Math.max(0, ML + (S.range[0] / DUR) * geom.pw0 * zoom - 0.05 * scroller.clientWidth); } }, 'Zoom to selection') : null,
      h('button', { class: 'btn', type: 'button', title: 'Show the whole run', disabled: zoom <= 1, onclick: () => { zoom = 1; draw(); scroller.scrollLeft = 0; } }, 'Fit'));
    legend.appendChild(h('span', { style: { marginLeft: 'auto', display: 'inline-flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, S.range ? h('button', { class: 'btn', type: 'button', onclick: () => setState({ range: null }) }, 'Clear time range · ' + fmtAt(S.range[0]) + ' – ' + fmtAt(S.range[1])) : null, zb));
    const fnd = DATA.findings.filter(f => f.severity !== 'info' && f.t > 0 && f.events.length);
    const lanes = KINDS.filter(k => S.kinds[k.id] && byKind[k.id].length);
    const W = Math.max(320, wrap.clientWidth || 800), LW = W < 560 ? 0 : 96, VW = W - LW, pw0 = Math.max(200, VW - ML - MR), pw = pw0 * z, svgW = pw + ML + MR;
    geom = { pw0 };
    const FL = fnd.length ? 36 : 0, LH = 26, T = 6, B = 22, ph = FL + lanes.length * LH, H = T + ph + B, x = t => ML + Math.min(1, Math.max(0, t / DUR)) * pw;
    // fixed label column
    clear(labels); labels.setAttribute('width', LW); labels.setAttribute('height', H); labels.style.display = LW ? '' : 'none';
    if (LW) {
      if (FL) { labels.appendChild(s('text', { x: 10, y: T + FL / 2 + 3.5, class: 'lane-label' }, 'Findings')); labels.appendChild(s('text', { x: LW - 6, y: T + FL / 2 + 3.5, 'text-anchor': 'end', class: 'lane-count' }, fmtN(fnd.length))); }
      lanes.forEach((k, i) => { const cy = T + FL + i * LH + LH / 2; labels.appendChild(marker(k.shape, 14, cy, 3.6, KC[k.id])); labels.appendChild(s('text', { x: 24, y: cy + 3.5, class: 'lane-label' }, k.label)); labels.appendChild(s('text', { x: LW - 6, y: cy + 3.5, 'text-anchor': 'end', class: 'lane-count' }, fmtN(byKind[k.id].length))); });
    }
    const svg = s('svg', { class: 'chart', width: svgW, height: H, viewBox: `0 0 ${svgW} ${H}`, role: 'img', 'aria-label': `Activity over time: one row per event kind${fnd.length ? ', with findings marked along the top' : ''}${z > 1 ? ', zoomed to ' + z.toFixed(1) + ' times' : ''}. Use the table view for the exact numbers.` });
    const ax = s('g', { class: 'axis' });
    const ticks = timeTicks(0, DUR, Math.max(3, Math.floor(pw / 90))), step = ticks.length > 1 ? ticks[1] - ticks[0] : DUR;
    for (const t of ticks) { ax.appendChild(s('line', { x1: x(t), x2: x(t), y1: T, y2: T + ph, class: 'gridline' })); ax.appendChild(s('text', { x: x(t), y: H - 6, 'text-anchor': 'middle' }, tickText(t, step))); }
    svg.appendChild(ax);
    lanes.forEach((k, i) => {
      const y0 = T + FL + i * LH, cy = y0 + LH / 2, list = byKind[k.id];
      svg.appendChild(s('line', { x1: 0, x2: svgW, y1: y0 + LH, y2: y0 + LH, class: 'gridline' }));
      if (list.length <= pw / 2.4) for (const e of list) svg.appendChild(marker(k.shape, x(e.t), cy, 3.6, KC[k.id]));
      else {   // too many to mark one by one: a density strip, 3px columns whose height says how many fall in each
        const cols = Math.max(1, Math.floor(pw / 3)), cnt = new Array(cols).fill(0); for (const e of list) cnt[Math.min(cols - 1, Math.floor(e.t / DUR * cols))]++;
        const mx = Math.max(...cnt);
        cnt.forEach((c, j) => { if (c) { const hh = Math.max(3, (LH - 8) * Math.pow(c / mx, 0.6)); svg.appendChild(s('rect', { x: ML + j * 3, y: cy - hh / 2, width: 2, height: hh, rx: 1, fill: KC[k.id] })); } });
      }
    });
    if (FL) {   // findings: the same glyphs as the severity pills, with a faint stem down through every lane
      svg.appendChild(s('line', { x1: 0, x2: svgW, y1: T + FL, y2: T + FL, class: 'gridline' }));
      for (const f of fnd) {
        const fx = x(f.t), g = icon(SEVICON[f.severity], 15); g.setAttribute('x', fx - 7.5); g.setAttribute('y', T + FL / 2 - 7.5); g.style.color = SEVC[f.severity]; g.style.fill = cssv('--surface');
        svg.appendChild(s('line', { x1: fx, x2: fx, y1: T + FL - 4, y2: T + ph, stroke: SEVC[f.severity], 'stroke-width': 1, 'stroke-dasharray': f.severity === 'high' ? '' : '3 3', opacity: 0.35, 'pointer-events': 'none' }));
        svg.appendChild(g);
      }
    }
    if (DATA.integrity.untrusted_after_mono) {
      const ux = x(untrustedAt());
      svg.appendChild(s('rect', { x: ux, y: T, width: Math.max(0, svgW - MR - ux), height: ph, fill: ink(0.07), 'pointer-events': 'none' }));
      svg.appendChild(s('line', { x1: ux, x2: ux, y1: T, y2: T + ph, stroke: cssv('--critical'), 'stroke-width': 1.5, 'pointer-events': 'none' }));
      svg.appendChild(s('text', { x: ux + 6, y: T + 12, fill: cssv('--t-critical'), 'font-size': 10.5, 'font-weight': 700, 'pointer-events': 'none' }, 'UNTRUSTED'));
    }
    const cross = s('line', { y1: T, y2: T + ph, stroke: ink(0.35), 'stroke-width': 1, display: 'none', 'pointer-events': 'none' });
    const sel = s('rect', { y: T, height: ph, class: 'brush-sel', display: S.range ? '' : 'none', 'pointer-events': 'none' });
    if (S.range) { sel.setAttribute('x', x(S.range[0])); sel.setAttribute('width', Math.max(2, x(S.range[1]) - x(S.range[0]))); }
    svg.appendChild(cross); svg.appendChild(sel);
    const hit = s('rect', { x: ML, y: T, width: pw, height: ph, fill: 'transparent', style: { cursor: 'crosshair' } });
    const tAt = ev => { const r = svg.getBoundingClientRect(); return Math.max(0, Math.min(DUR, ((ev.clientX - r.left - ML) / pw) * DUR)); };
    const near = (list, t, px) => list.filter(e => Math.abs(x(e.t) - x(t)) <= px);
    const findingAt = ev => { const r = svg.getBoundingClientRect(), y = ev.clientY - r.top; return (FL && y < T + FL) ? near(fnd, tAt(ev), 9) : []; };
    let drag = null;
    hit.addEventListener('pointermove', ev => {
      const t = tAt(ev), cx = x(t), r = svg.getBoundingClientRect(), y = ev.clientY - r.top;
      cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.setAttribute('display', '');
      if (drag !== null) { const a = Math.min(drag, t), zz = Math.max(drag, t); sel.setAttribute('display', ''); sel.setAttribute('x', x(a)); sel.setAttribute('width', Math.max(2, x(zz) - x(a))); }
      const li = Math.floor((y - T - FL) / LH), kind = li >= 0 ? lanes[li] : null, rows = [];
      if (FL && y < T + FL) for (const f of near(fnd, t, 9).slice(0, 4)) rows.push(h('div', { class: 'tk' }, h('span', { class: 'tv' }, f.severity.toUpperCase()), h('span', { class: 'tip-l' }, short(f.title, 70))));
      else if (kind) { const hits = near(byKind[kind.id], t, 5); for (const e of hits.slice(0, 4)) rows.push(h('div', { class: 'tk' }, h('span', { class: 'tv num' }, fmtAt(e.t)), h('span', { class: 'tip-l' }, short(e.title, 70)))); if (hits.length > 4) rows.push(h('div', { class: 'tip-l' }, '+' + (hits.length - 4) + ' more here')); }
      showTip(ev.clientX, ev.clientY, [h('div', { class: 'tip-l' }, fmtAt(t) + (kind ? ' · ' + kind.label : '')), ...rows]);
    });
    hit.addEventListener('pointerleave', () => { cross.setAttribute('display', 'none'); hideTip(); });
    hit.addEventListener('pointerdown', ev => { hit.setPointerCapture(ev.pointerId); drag = tAt(ev); });
    hit.addEventListener('pointerup', ev => {
      const a = Math.min(drag, tAt(ev)), zz = Math.max(drag, tAt(ev)); drag = null;
      if (x(zz) - x(a) > 4) setState({ range: [a, zz] });
      else { const f = findingAt(ev)[0]; if (f) setState({ sel: { type: 'finding', id: f.id } }); else if (S.range) setState({ range: null }); }   // a click on a finding's mark opens it
    });
    svg.appendChild(hit);
    const keep = scroller.scrollLeft;
    clear(scroller).appendChild(svg); scroller.scrollLeft = keep;
  }
  scroller.addEventListener('wheel', ev => {   // Ctrl/Cmd + wheel (and a trackpad pinch, which arrives as Ctrl + wheel) zooms around the pointer; a plain wheel still scrolls the page
    if (!(ev.ctrlKey || ev.metaKey)) return;
    ev.preventDefault(); zoomTo(zoom * Math.exp(-ev.deltaY * 0.0025), ev.clientX - scroller.getBoundingClientRect().left);
  }, { passive: false });
  scroller.addEventListener('keydown', ev => {
    if (ev.target !== scroller || ev.ctrlKey || ev.metaKey || ev.altKey) return;
    if (ev.key === '+' || ev.key === '=') { ev.preventDefault(); zoomTo(zoom * 1.6, centre()); } else if (ev.key === '-') { ev.preventDefault(); zoomTo(zoom / 1.6, centre()); }
  });
  wrap.redraw = draw;
  new ResizeObserver(() => { if (wrap.isConnected && wrap.clientWidth) draw(); }).observe(wrap);
  onState(() => { if (wrap.isConnected) draw(); });
  requestAnimationFrame(draw);
  return wrap;
}
function activityTable() {
  const b = bucketize(DATA.events, 24);
  const head = h('tr', null, h('th', { scope: 'col' }, 'Time window'), ...KINDS.map(k => h('th', { scope: 'col' }, k.label)));
  const rows = b.filter(x => KINDS.some(k => x.c[k.id])).map(x => h('tr', null, h('td', null, fmtAt(x.t0) + ' – ' + fmtAt(x.t1)), ...KINDS.map(k => h('td', { class: 'num' }, fmtN(x.c[k.id])))));
  return h('div', { style: { overflow: 'auto', maxHeight: '320px' } }, h('table', { class: 'plain' }, h('thead', null, head), h('tbody', null, rows)));
}

/* ranked horizontal bars (one hue; the "direct" row is emphasised with a status colour AND a label) */
function rankedBars(items, opts) {
  opts = opts || {};
  const max = Math.max(1, ...items.map(i => i.value));
  const wrap = h('div', { role: 'list' });
  if (!items.length) return h('div', { class: 'emptystate compact' }, icon('info', 24), h('p', null, opts.empty || 'Nothing recorded'));
  for (const it of items) {
    const row = h('div', { class: 'bar-row' + (it.flag ? ' direct' : ''), role: 'listitem', tabindex: '0', onclick: it.onclick, onkeydown: ev => { if (ev.key === 'Enter' && it.onclick) it.onclick(); } },
      h('div', { class: 'n', title: it.label + (it.sev ? ' (' + it.sev + ' finding)' : '') }, it.flag ? h('span', { class: 'sev sev-medium', style: { marginRight: '6px' } }, 'DIRECT') : null, it.sev ? h('span', { class: 'sev sev-' + it.sev, style: { marginRight: '6px', padding: '0 4px' }, title: it.sev + ' finding' }, icon(SEVICON[it.sev], 11)) : null, it.label),
      h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill', style: { width: (100 * it.value / max) + '%' } })),
      h('div', { class: 'num muted' }, it.right ?? fmtN(it.value)));
    row.addEventListener('pointermove', ev => showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv num' }, it.right ?? fmtN(it.value)), h('div', { class: 'tt' }, it.label), it.sub ? h('div', { class: 'tip-l' }, it.sub) : null]));
    row.addEventListener('pointerleave', hideTip);
    wrap.appendChild(row);
  }
  return wrap;
}
function rankedTable(items, cols) {
  return h('div', { style: { overflow: 'auto', maxHeight: '320px' } }, h('table', { class: 'plain' }, h('thead', null, h('tr', null, h('th', { scope: 'col' }, cols[0]), h('th', { scope: 'col' }, cols[1]))),
    h('tbody', null, items.map(i => h('tr', null, h('td', null, i.label), h('td', { class: 'num' }, i.right ?? fmtN(i.value)))))));
}

/* coverage strip: where the recording is trustworthy and where it has gaps */
const relMono = m => m + DATA.clock.offset_ns - DATA.clock.t0_tracee_ns;
// where the trusted part of the recording ends, clamped into the run so a clock oddity can never print an absurd time
const untrustedAt = () => DATA.integrity.untrusted_after_mono ? Math.min(DUR, Math.max(0, relMono(DATA.integrity.untrusted_after_mono))) : null;
function coverageStrip() {
  const lanes = [['Kernel', 'tracee'], ['Proxy', 'proxy'], ['Recorder', 'recorder']];
  const gaps = DATA.integrity.gaps || [];
  const wrap = h('div', { class: 'cov' });
  for (const [label, key] of lanes) {
    const lane = h('div', { class: 'lane', role: 'img', 'aria-label': label + ' coverage' });
    const mine = gaps.filter(g => g.source === key);
    for (const g of mine) {
      const a = Math.max(0, relMono(g.start_mono)), z = g.end_mono ? relMono(g.end_mono) : DUR;
      const gap = h('div', { class: 'gap', style: { left: (100 * a / DUR) + '%', width: Math.max(0.8, 100 * (z - a) / DUR) + '%' } });
      gap.addEventListener('pointermove', ev => showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv' }, 'Gap in ' + label), h('div', { class: 'tip-l' }, g.reason), h('div', { class: 'tt' }, fmtAt(a) + ' → ' + fmtAt(z))]));
      gap.addEventListener('pointerleave', hideTip);
      lane.appendChild(gap);
    }
    if (DATA.integrity.untrusted_after_mono) {
      const ua = untrustedAt();
      const band = h('div', { class: 'untrusted', style: { left: (100 * ua / DUR) + '%', width: (100 - 100 * ua / DUR) + '%' } });
      band.addEventListener('pointermove', ev => showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv' }, 'Untrusted'), h('div', { class: 'tip-l' }, 'The recorder had died: nothing after ' + fmtAt(ua) + ' can be vouched for.')]));
      band.addEventListener('pointerleave', hideTip);
      lane.appendChild(band);
    }
    wrap.appendChild(h('div', null, label)); wrap.appendChild(lane);
  }
  if (DATA.integrity.untrusted_after_mono) wrap.appendChild(h('div', { class: 'cov-note' }, 'Hatched with a red edge: the recorder died here; data after it is untrusted.'));
  return wrap;
}

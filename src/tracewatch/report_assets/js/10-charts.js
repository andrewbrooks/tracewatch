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
    const W = Math.max(320, wrap.clientWidth || 800), pw = W - M.l - M.r, ph = H - M.t - M.b;
    const buckets = bucketize(DATA.events.filter(e => !(e.kind === 'udp' && e.detail.probe && !S.probes)), N);
    const on = KINDS.filter(k => S.kinds[k.id]);
    const totals = Object.fromEntries(KINDS.map(k => [k.id, buckets.reduce((a, b) => a + b.c[k.id], 0)]));
    legendDraw(totals);
    const maxc = Math.max(1, ...buckets.map(b => on.reduce((a, k) => a + b.c[k.id], 0)));
    const ticks = niceTicks(maxc, 4), ymax = ticks[ticks.length - 1] || 1, sy = ph / ymax, bw = pw / N, thick = Math.min(24, bw - 2);
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
    // hover layer: crosshair band + tooltip listing every kind at that bucket
    const band = s('rect', { y: M.t, height: ph, width: bw, fill: 'rgba(255,255,255,.06)', display: 'none', 'pointer-events': 'none' });
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
      const rows = on.map(k => h('div', { class: 'tk' }, h('span', { class: 'keyln', style: { background: KC[k.id] } }), h('span', { class: 'tv num' }, fmtN(b.c[k.id])), h('span', { class: 'tl' }, k.label)));
      showTip(ev.clientX, ev.clientY, [h('div', { class: 'tl' }, fmtAt(b.t0) + ' – ' + fmtAt(b.t1)), rows]);
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
  if (!items.length) return h('div', { class: 'empty' }, opts.empty || 'Nothing recorded');
  for (const it of items) {
    const row = h('div', { class: 'bar-row' + (it.flag ? ' direct' : ''), role: 'listitem', tabindex: '0', onclick: it.onclick, onkeydown: ev => { if (ev.key === 'Enter' && it.onclick) it.onclick(); } },
      h('div', { class: 'n', title: it.label }, it.flag ? h('span', { class: 'sev sev-medium', style: { marginRight: '6px' } }, 'DIRECT') : null, it.label),
      h('div', { class: 'bar-track' }, h('div', { class: 'bar-fill', style: { width: (100 * it.value / max) + '%' } })),
      h('div', { class: 'num muted' }, it.right ?? fmtN(it.value)));
    row.addEventListener('pointermove', ev => showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv num' }, it.right ?? fmtN(it.value)), h('div', { class: 'tt' }, it.label), it.sub ? h('div', { class: 'tl' }, it.sub) : null]));
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
      gap.addEventListener('pointermove', ev => showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv' }, 'Gap in ' + label), h('div', { class: 'tl' }, g.reason), h('div', { class: 'tt' }, fmtAt(a) + ' → ' + fmtAt(z))]));
      gap.addEventListener('pointerleave', hideTip);
      lane.appendChild(gap);
    }
    wrap.appendChild(h('div', null, label)); wrap.appendChild(lane);
  }
  return wrap;
}

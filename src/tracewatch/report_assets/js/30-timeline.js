/* ===== timeline: one swim-lane per process (lifeline + typed markers), row-virtualised, drag-to-zoom ===== */
function timelineView() {
  const LABEL_W = 236, ROW = 28, PAD_R = 18;
  let flaggedOnly = false, hover = null;
  const nav = activityChart({ height: 80, buckets: 90, left: LABEL_W, right: PAD_R, noX: true });
  const flagBtn = h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', onclick: () => { flaggedOnly = !flaggedOnly; flagBtn.setAttribute('aria-pressed', String(flaggedOnly)); draw(); } }, 'Flagged processes only');
  const probeBtn = h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', title: 'UDP connect() calls made by getaddrinfo right after a lookup: address sorting, not traffic', onclick: () => { setState({ probes: !S.probes }); probeBtn.setAttribute('aria-pressed', String(S.probes)); } }, 'Show lookup probes');
  const reset = h('button', { class: 'btn', type: 'button', onclick: () => setState({ range: null }) }, 'Reset zoom');
  const toolbar = h('div', { class: 'toolbar' }, flagBtn, probeBtn, reset, h('span', { class: 'muted', style: { marginLeft: 'auto' } }, 'Drag the axis (or the chart above) to zoom · click a marker or lane for details'));
  const axisHolder = h('div', { style: { borderBottom: '1px solid var(--line)', background: 'var(--surface)', flex: 'none' } });
  const scroller = h('div', { class: 'tl', tabindex: '0', role: 'group', 'aria-label': 'Timeline rows. Scroll with the arrow keys.' });
  const navWrap = h('div', { style: { padding: '8px 0 0', background: 'var(--surface)', borderBottom: '1px solid var(--line)', flex: 'none' } }, nav);
  const root = h('div', { class: 'view fill', id: 'view-timeline' }, toolbar, navWrap, axisHolder, scroller);
  let rows = [], W = 900, d0 = 0, d1 = DUR, bodySvg = null, spacer = null, raf = 0;

  function computeRows() {
    const out = [];
    for (const p of DATA.processes) {
      if (flaggedOnly && !(p.severity === 'medium' || p.severity === 'high')) continue;
      const evs = (evByProc.get(p.id) || []).filter(e => e.kind !== 'exit' && S.kinds[groupOf(e)] && !(e.kind === 'udp' && e.detail.probe && !S.probes));
      if (S.q && !qmatch(p.name, p.cmdline, p.pid) && !evs.some(e => qmatch(e.title))) continue;
      out.push({ p, evs });
    }
    const loose = DATA.events.filter(e => !e.proc && S.kinds[groupOf(e)]);
    if (loose.length) out.push({ p: null, evs: loose });
    return out;
  }
  const xOf = t => LABEL_W + ((t - d0) / Math.max(1, d1 - d0)) * (W - LABEL_W - PAD_R);
  const tOf = px => d0 + ((px - LABEL_W) / (W - LABEL_W - PAD_R)) * (d1 - d0);

  function drawAxis() {
    const svg = s('svg', { width: W, height: 30, role: 'img', 'aria-label': 'Time axis. Drag to zoom into a range.' }), g = s('g', { class: 'axis' });
    for (const t of timeTicks(d0, d1, Math.max(3, Math.floor((W - LABEL_W) / 95)))) { g.appendChild(s('line', { x1: xOf(t), x2: xOf(t), y1: 20, y2: 30 })); g.appendChild(s('text', { x: xOf(t), y: 14, 'text-anchor': 'middle' }, tickLabel(t, d1 - d0))); }
    svg.appendChild(g);
    const sel = s('rect', { class: 'brush-sel', y: 0, height: 30, display: 'none' }), hit = s('rect', { x: LABEL_W, y: 0, width: W - LABEL_W, height: 30, fill: 'transparent', style: { cursor: 'ew-resize' } });
    let a = null;
    hit.addEventListener('pointerdown', ev => { hit.setPointerCapture(ev.pointerId); a = ev.clientX - svg.getBoundingClientRect().left; });
    hit.addEventListener('pointermove', ev => { if (a === null) return; const b = ev.clientX - svg.getBoundingClientRect().left; sel.setAttribute('display', ''); sel.setAttribute('x', Math.min(a, b)); sel.setAttribute('width', Math.abs(b - a)); });
    hit.addEventListener('pointerup', ev => { const b = ev.clientX - svg.getBoundingClientRect().left; const lo = Math.min(a, b), hi = Math.max(a, b); a = null; sel.setAttribute('display', 'none'); if (hi - lo > 5) setState({ range: [Math.max(0, tOf(lo)), Math.min(DUR, tOf(hi))] }); });
    svg.appendChild(sel); svg.appendChild(hit);
    clear(axisHolder).appendChild(svg);
  }
  function drawRows() {
    const top = scroller.scrollTop, vh = scroller.clientHeight || 500, i0 = Math.max(0, Math.floor(top / ROW) - 4), i1 = Math.min(rows.length, Math.ceil((top + vh) / ROW) + 4);
    const sel = S.sel && S.sel.type === 'proc' ? S.sel.id : null;
    const g = s('g');
    for (let i = i0; i < i1; i++) {
      const r = rows[i], y = i * ROW, cy = y + ROW / 2, p = r.p, isSel = p && p.id === sel;
      g.appendChild(s('rect', { class: 'tl-row-bg', x: 0, y, width: W, height: ROW, fill: isSel ? 'rgba(57,135,229,.12)' : 'transparent', 'data-i': i }));
      g.appendChild(s('line', { x1: 0, x2: W, y1: y + ROW, y2: y + ROW, class: 'gridline' }));
      const label = p ? short(p.name, 26) : 'unattributed';
      const indent = p ? Math.min(p.depth, 6) * 9 : 0;
      const lab = s('text', { class: 'tl-label' + (isSel ? ' sel' : ''), x: 12 + indent, y: cy + 4, style: { cursor: 'pointer' } }, label);
      if (p) { lab.addEventListener('click', () => setState({ sel: { type: 'proc', id: p.id } })); g.appendChild(s('text', { class: 'tl-sub', x: LABEL_W - 10, y: cy + 4, 'text-anchor': 'end' }, String(p.pid))); }
      g.appendChild(lab);
      if (p && p.severity && (p.severity === 'high' || p.severity === 'medium' || p.severity === 'low')) g.appendChild(s('rect', { x: 0, y: y + 4, width: 3, height: ROW - 8, fill: SEVC[p.severity], rx: 1.5 }));
      if (p) {
        const a = Math.max(xOf(p.start), LABEL_W), z = p.end === null ? W - PAD_R : Math.min(xOf(p.end), W - PAD_R);
        if (z > LABEL_W && a < W - PAD_R && xOf(p.start) < W) {
          const tint = p.exit && p.exit.signal ? SEVC.high : p.exit && p.exit.code ? SEVC.medium : null;
          g.appendChild(s('rect', { x: a, y: cy - 3, width: Math.max(2, z - a), height: 6, rx: 3, fill: tint || ink(0.16), opacity: tint ? 0.85 : 1, stroke: p.end === null ? cssv('--text-3') : 'none', 'stroke-dasharray': p.end === null ? '3 3' : null }));
        }
      }
      for (const e of r.evs) {
        if (e.t < d0 || e.t > d1) continue;
        const kk = KINDS.find(z => z.id === groupOf(e)), x = xOf(e.t), isSelEv = S.sel && S.sel.type === 'event' && S.sel.id === e.id;
        g.appendChild(marker(kk.shape, x, cy, isSelEv ? 5.6 : 4, KC[kk.id]));
      }
    }
    for (const re of DATA.recorder_events) {
      if (!['component_died', 'cap_reached', 'target_stopped', 'target_killed'].includes(re.kind) || re.t < d0 || re.t > d1) continue;
      const x = xOf(re.t); g.appendChild(s('line', { x1: x, x2: x, y1: 0, y2: rows.length * ROW, stroke: cssv('--k-sys'), 'stroke-width': 1.5, 'stroke-dasharray': '4 3' }));
    }
    clear(bodySvg).appendChild(g);
    bodySvg.insertBefore(spacer, g);
    bodySvg.dataset.i0 = i0;
  }
  function draw() {
    if (!root.classList.contains('on')) return;
    rows = computeRows(); W = Math.max(520, scroller.clientWidth - 2);
    [d0, d1] = S.range ? S.range : [0, DUR];
    reset.disabled = !S.range;
    drawAxis();
    bodySvg = s('svg', { class: 'tl-hit', width: W, height: Math.max(rows.length * ROW, 40), role: 'img', 'aria-label': 'Timeline of process lifelines and events. The Events tab lists the same data as a table.' });
    spacer = s('rect', { x: 0, y: 0, width: 1, height: 1, fill: 'transparent' });
    clear(scroller).appendChild(bodySvg);
    drawRows();
    if (!rows.length) scroller.appendChild(DATA.processes.length ? emptyState('search', 'No processes match', 'The current search, kind or flagged-only filters hide every lane.', h('button', { class: 'btn', type: 'button', onclick: () => { const i = $('#search'); if (i) i.value = ''; setState({ q: '', range: null, kinds: Object.fromEntries(KINDS.map(k => [k.id, true])) }); } }, 'Reset filters')) : emptyState('timeline', 'No processes were recorded', 'There is nothing to lay out on a timeline.'));
    const rowAt = ev => { const r = bodySvg.getBoundingClientRect(); return rows[Math.floor((ev.clientY - r.top) / ROW)] || null; };
    bodySvg.addEventListener('pointermove', ev => {
      const r = rowAt(ev); if (!r) { hideTip(); return; }
      const box = bodySvg.getBoundingClientRect(), mx = ev.clientX - box.left;
      let best = null, bd = 14;
      for (const e of r.evs) { if (e.t < d0 || e.t > d1) continue; const d = Math.abs(xOf(e.t) - mx); if (d < bd) { bd = d; best = e; } }
      hover = best;
      if (best) showTip(ev.clientX, ev.clientY, [h('div', { class: 'tip-l' }, KINDS.find(z => z.id === groupOf(best)).label + ' · ' + fmtAt(best.t)), h('div', { class: 'tt' }, short(oneLine(best.title), 240)), r.p ? h('div', { class: 'tip-l' }, pLabel(r.p.id)) : null]);
      else if (r.p) showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv' }, r.p.name + ' · ' + r.p.pid), h('div', { class: 'tip-l' }, (r.p.exit ? r.p.exit.status : 'no exit recorded') + ' · ' + fmtAt(r.p.start) + ' → ' + fmtAt(r.p.end))]); else hideTip();
    });
    bodySvg.addEventListener('pointerleave', hideTip);
    bodySvg.addEventListener('click', ev => { if (hover) setState({ sel: { type: 'event', id: hover.id } }); else { const r = rowAt(ev); if (r && r.p && ev.clientX - bodySvg.getBoundingClientRect().left > LABEL_W) setState({ sel: { type: 'proc', id: r.p.id } }); } });
  }
  scroller.addEventListener('scroll', () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; if (bodySvg) drawRows(); }); });
  new ResizeObserver(() => { if (root.classList.contains('on')) draw(); }).observe(scroller);
  root.onShow = draw;
  onState(() => { probeBtn.setAttribute('aria-pressed', String(S.probes)); if (root.classList.contains('on')) draw(); });
  return root;
}

/* ===== process tree: layered node-link graph, pan/zoom, collapse, lineage highlight, flagged-only ===== */
function treeView() {
  const NW = 252, NH = 60, GX = 56, GY = 12, ROOT_GAP = 40;
  const collapsed = new Set();
  let flaggedOnly = false, tx = 24, ty = 24, k = 1, first = true, nodes = [], pos = new Map();
  if (DATA.processes.length > 120) for (const p of DATA.processes) if (p.depth >= 2 && p.children.length) collapsed.add(p.id);

  const world = s('g'), edgeG = s('g'), nodeG = s('g');
  world.appendChild(edgeG); world.appendChild(nodeG);
  const svg = s('svg', { role: 'tree', 'aria-label': 'Process tree. Select a process to see its command line, chain and activity.' }, s('defs', null, s('clipPath', { id: 'nclip' }, s('rect', { x: 0, y: 0, width: NW - 8, height: NH, rx: 8 }))), world);
  const canvas = h('div', { class: 'canvas' }, svg);
  const legend = h('div', { class: 'legend-float' },
    h('span', { style: { display: 'inline-flex', gap: '6px', alignItems: 'center' } }, h('i', { class: 'kdot', style: { background: SEVC.high } }), 'high'),
    h('span', { style: { display: 'inline-flex', gap: '6px', alignItems: 'center' } }, h('i', { class: 'kdot', style: { background: SEVC.medium } }), 'medium'),
    h('span', { style: { display: 'inline-flex', gap: '6px', alignItems: 'center' } }, h('i', { class: 'kdot', style: { background: SEVC.low } }), 'low'),
    h('span', { class: 'muted' }, 'left bar = most severe finding on that process · drag to pan · wheel to zoom'));
  canvas.appendChild(legend);

  const btn = (label, fn, pressed) => h('button', { class: 'btn', type: 'button', onclick: fn, 'aria-pressed': pressed === undefined ? undefined : String(pressed) }, label);
  const flagBtn = btn('Flagged paths only', () => { flaggedOnly = !flaggedOnly; flagBtn.setAttribute('aria-pressed', String(flaggedOnly)); render(true); }, false);
  const info = h('span', { class: 'muted num' });
  const toolbar = h('div', { class: 'toolbar' },
    btn('Fit all', () => fit(true)), btn('Expand all', () => { collapsed.clear(); render(true); }),
    btn('Collapse to depth 2', () => { collapsed.clear(); for (const p of DATA.processes) if (p.depth >= 1 && p.children.length) collapsed.add(p.id); render(true); }), flagBtn, info);
  const root = h('div', { class: 'view fill', id: 'view-tree' }, toolbar, canvas);

  const flaggedSet = (() => {                       // processes with a medium+ finding, and every ancestor of one
    const f = new Set(); for (const p of DATA.processes) if (p.severity === 'medium' || p.severity === 'high') for (const c of chainOf(p.id)) f.add(c.id); return f;
  })();
  const matches = () => { if (!S.q) return null; const m = new Set(); for (const p of DATA.processes) if (qmatch(p.name, p.cmdline, p.pid, p.cwd)) m.add(p.id); return m; };

  function layout() {
    pos = new Map(); let leaf = 0, maxX = 0;
    const vis = id => !flaggedOnly || flaggedSet.has(id);
    function place(p, depth) {
      const kids = collapsed.has(p.id) ? [] : p.children.filter(vis).map(id => P.get(id));
      const n = { p, depth, x: depth * (NW + GX), kids: [], hidden: collapsed.has(p.id) ? p.children.length : 0 };
      if (!kids.length) { n.y = leaf * (NH + GY); leaf++; } else { for (const c of kids) n.kids.push(place(c, depth + 1)); n.y = (n.kids[0].y + n.kids[n.kids.length - 1].y) / 2; }
      pos.set(p.id, n); maxX = Math.max(maxX, n.x + NW); return n;
    }
    for (const p of DATA.processes) if (!p.parent && vis(p.id)) { place(p, 0); leaf += ROOT_GAP / (NH + GY); }
    return { w: maxX, h: Math.max(NH, leaf * (NH + GY)) };
  }
  function apply() { world.setAttribute('transform', `translate(${tx},${ty}) scale(${k})`); }
  function fit(full) {
    const b = layout(), W = canvas.clientWidth || 900, H = canvas.clientHeight || 500;
    if (full) { k = Math.min(1, Math.max(0.12, Math.min((W - 60) / b.w, (H - 60) / b.h))); tx = 30; ty = 30 + Math.max(0, (H - 60 - b.h * k) / 2); }
    else {                                       // readable by default, centred on the root; "Fit all" zooms out
      k = Math.min(1, Math.max(0.85, (W - 60) / b.w)); tx = 30;
      const r = DATA.processes.find(p => !p.parent && pos.get(p.id)), rn = r && pos.get(r.id);
      ty = rn ? Math.max(Math.min(30, H / 2 - (rn.y + NH / 2) * k), H / 2 - (rn.y + NH / 2) * k) : 30;
    }
    apply();
  }
  function exitTag(p) {
    if (!p.exit) return { t: 'no exit', c: cssv('--text-3') };
    if (p.exit.signal) return { t: p.exit.signal_name.replace('SIG', ''), c: cssv('--t-critical') };
    return p.exit.code === 0 ? { t: 'exit 0', c: cssv('--text-3') } : { t: 'exit ' + p.exit.code, c: cssv('--t-serious') };
  }
  function render(refit) {
    const b = layout(), m = matches(), sel = S.sel && S.sel.type === 'proc' ? S.sel.id : null;
    const path = new Set(sel ? chainOf(sel).map(p => p.id) : []), sub = new Set(sel ? [sel, ...descendants(sel)] : []);
    clear(edgeG); clear(nodeG);
    let count = 0;
    for (const [id, n] of pos) {
      count++;
      for (const c of n.kids) {
        const x1 = n.x + NW, y1 = n.y + NH / 2, x2 = c.x, y2 = c.y + NH / 2, mx = (x2 - x1) / 2;
        const hl = sel && ((path.has(n.p.id) && path.has(c.p.id)) || (sub.has(n.p.id) && sub.has(c.p.id)));
        edgeG.appendChild(s('path', { d: `M${x1},${y1}C${x1 + mx},${y1} ${x2 - mx},${y2} ${x2},${y2}`, class: 'edge' + (hl ? ' hl' : '') + (first ? ' draw' : ''), 'pointer-events': 'none' }));
      }
    }
    for (const [id, n] of pos) {
      const p = n.p, sevc = p.severity ? SEVC[p.severity] : null, ex = exitTag(p), ev = evByProc.get(id) || [];
      const cnt = k_ => ev.filter(e => groupOf(e) === k_ && e.kind !== 'exit' && !(e.kind === 'udp' && e.detail.probe)).length;
      const g = s('g', { class: 'node' + (id === sel ? ' sel' : '') + (path.has(id) && id !== sel ? ' onpath' : '') + (p.severity === 'high' || p.severity === 'medium' ? ' flag-' + p.severity : '') + (m && !m.has(id) ? ' dimmed' : ''), transform: `translate(${n.x},${n.y})`, tabindex: '0', role: 'treeitem', 'aria-label': `${p.name} pid ${p.pid}, ${p.exit ? p.exit.status : 'no exit recorded'}${p.severity ? ', ' + p.severity + ' severity finding' : ''}`, 'aria-selected': String(id === sel) });
      g.appendChild(s('rect', { class: 'nbox', width: NW - 8, height: NH, rx: 9 }));
      const inner = s('g', { 'clip-path': 'url(#nclip)' });
      if (sevc) inner.appendChild(s('rect', { x: 0, y: 0, width: 4, height: NH, fill: sevc }));
      inner.appendChild(s('path', { d: ICONS.commands, transform: 'translate(12,9) scale(.6)', fill: 'none', stroke: p.forked ? cssv('--faint') : cssv('--text-2'), 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
      inner.appendChild(s('text', { class: 'nm', x: 33, y: 20 }, short(p.name, p.severity ? 15 : 22), p.forked ? s('tspan', { class: 'pidt', dx: 6 }, 'fork') : null));
      if (p.severity && p.severity !== 'info') inner.appendChild(s('text', { class: 'sevt', x: NW - 22 - String(p.pid).length * 6.4, y: 19, 'text-anchor': 'end', fill: cssv('--t-' + ({ high: 'critical', medium: 'serious', low: 'warning' })[p.severity]) }, p.severity === 'medium' ? 'MED' : p.severity.toUpperCase()));
      inner.appendChild(s('text', { class: 'pidt', x: NW - 16, y: 19, 'text-anchor': 'end' }, String(p.pid)));
      const argsOnly = p.argv && p.argv.length > 1 ? p.argv.slice(1).join(' ') : '';
      inner.appendChild(s('text', { class: 'cm', x: 14, y: 36 }, short(oneLine('$ ' + (argsOnly || p.cmdline)), 33)));
      let cx = 14;
      for (const kd of ['http', 'net', 'dns', 'file']) {
        const c = cnt(kd); if (!c) continue;
        const kk = KINDS.find(z => z.id === kd);
        inner.appendChild(marker(kk.shape, cx + 4, 50, 3.3, KC[kd]));
        inner.appendChild(s('text', { class: 'cnt2', x: cx + 11, y: 53.5 }, String(c)));
        cx += 14 + String(c).length * 6.4 + 6;
      }
      inner.appendChild(s('text', { class: 'ex', x: NW - 16, y: 53.5, 'text-anchor': 'end', fill: ex.c }, ex.t));
      g.appendChild(inner);
      if (p.children.length) {
        const cg = s('g', { transform: `translate(${NW - 8},${NH / 2})`, onclick: ev => { ev.stopPropagation(); collapsed.has(id) ? collapsed.delete(id) : collapsed.add(id); render(); }, role: 'button', 'aria-label': collapsed.has(id) ? 'Expand children' : 'Collapse children' });
        cg.appendChild(s('circle', { class: 'chev', r: 9 }));
        cg.appendChild(s('text', { class: 'chev-t', 'text-anchor': 'middle', y: 4 }, collapsed.has(id) ? '+' + p.children.length : '−'));
        g.appendChild(cg);
      }
      g.addEventListener('click', () => setState({ sel: { type: 'proc', id } }));
      g.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); setState({ sel: { type: 'proc', id } }); } });
      g.addEventListener('pointermove', ev => showTip(ev.clientX, ev.clientY, [h('div', { class: 'tv' }, p.name + ' · ' + p.pid), h('div', { class: 'tt' }, short(oneLine(p.cmdline), 220)), h('div', { class: 'tl' }, (p.exit ? p.exit.status : 'no exit recorded') + ' · ' + fmtAt(p.start) + ' → ' + fmtAt(p.end))]));
      g.addEventListener('pointerleave', hideTip);
      nodeG.appendChild(g);
    }
    info.textContent = `${count} of ${DATA.processes.length} processes shown`;
    if (refit) fit();
    first = false;
  }
  /* pan / zoom */
  let drag = null;
  canvas.addEventListener('pointerdown', ev => { if (ev.target.closest('.node')) return; drag = { x: ev.clientX, y: ev.clientY, tx, ty }; canvas.classList.add('drag'); canvas.setPointerCapture(ev.pointerId); });
  canvas.addEventListener('pointermove', ev => { if (!drag) return; tx = drag.tx + ev.clientX - drag.x; ty = drag.ty + ev.clientY - drag.y; apply(); });
  canvas.addEventListener('pointerup', () => { drag = null; canvas.classList.remove('drag'); });
  canvas.addEventListener('wheel', ev => {
    ev.preventDefault(); const r = canvas.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top, nk = Math.max(0.15, Math.min(2.6, k * Math.exp(-ev.deltaY * 0.0016)));
    tx = mx - (mx - tx) * (nk / k); ty = my - (my - ty) * (nk / k); k = nk; apply();
  }, { passive: false });
  function reveal(id) {
    let p = P.get(id); let changed = false;
    while (p && p.parent) { p = P.get(p.parent); if (collapsed.delete(p.id)) changed = true; }
    if (changed || flaggedOnly) { if (flaggedOnly && !flaggedSet.has(id)) { flaggedOnly = false; flagBtn.setAttribute('aria-pressed', 'false'); } render(); }
    const n = pos.get(id); if (!n) return;
    const W = canvas.clientWidth, H = canvas.clientHeight; tx = W / 2 - (n.x + NW / 2) * k; ty = H / 2 - (n.y + NH / 2) * k; apply();
  }
  root.onShow = () => { if (first || !pos.size) render(true); else render(); if (S.sel && S.sel.type === 'proc') reveal(S.sel.id); };
  onState(() => { if (root.classList.contains('on')) { render(); } });
  root.reveal = reveal;
  return root;
}

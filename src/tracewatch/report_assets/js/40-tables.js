/* ===== virtualised, sortable table. rows() is re-evaluated on refresh() so filters always apply. ===== */
function vtable(cfg) {
  const ROWH = cfg.rowHeight || 32;
  let sortKey = cfg.defaultSort || null, sortDir = cfg.defaultDir || 1, data = [], raf = 0;
  const grid = cfg.cols.map(c => c.w || '1fr').join(' ');
  const head = h('div', { class: 'tbl-head', style: { gridTemplateColumns: grid, minWidth: cfg.minWidth || '0' }, role: 'row' });
  const body = h('div', { class: 'tbl-body', role: 'rowgroup' });
  const empty = h('div', { class: 'empty', style: { display: 'none' } }, cfg.empty || 'Nothing to show');
  const wrap = h('div', { class: 'tbl-wrap', style: { flex: '1', minHeight: '160px', maxHeight: cfg.maxHeight || 'none' }, role: 'table', 'aria-label': cfg.label || 'table' }, head, body, empty);
  const count = h('span', { class: 'muted num' });
  for (const c of cfg.cols) {
    head.appendChild(h('button', { type: 'button', role: 'columnheader', title: c.sort ? 'Sort by ' + c.label : c.label, onclick: () => { if (!c.sort) return; if (sortKey === c.key) sortDir = -sortDir; else { sortKey = c.key; sortDir = 1; } refresh(); } }, c.label + (sortKey === c.key ? (sortDir > 0 ? ' ▲' : ' ▼') : '')));
  }
  function refresh() {
    data = cfg.rows().slice();
    const col = cfg.cols.find(c => c.key === sortKey);
    if (col && col.sort) data.sort((a, b) => { const x = col.sort(a), y = col.sort(b); return (x < y ? -1 : x > y ? 1 : 0) * sortDir; });
    $$('button', head).forEach((b, i) => { const c = cfg.cols[i]; b.textContent = c.label + (sortKey === c.key ? (sortDir > 0 ? ' ▲' : ' ▼') : ''); });
    body.style.height = data.length * ROWH + 'px'; empty.style.display = data.length ? 'none' : 'block';
    count.textContent = fmtN(data.length) + ' row' + (data.length === 1 ? '' : 's');
    if (cfg.onCount) cfg.onCount(data.length);
    paint();
  }
  function paint() {
    const top = wrap.scrollTop, vh = wrap.clientHeight || 400, i0 = Math.max(0, Math.floor(top / ROWH) - 6), i1 = Math.min(data.length, Math.ceil((top + vh) / ROWH) + 6);
    clear(body);
    for (let i = i0; i < i1; i++) {
      const r = data[i], sel = cfg.isSelected && cfg.isSelected(r);
      const row = h('div', { class: 'tbl-row' + (sel ? ' sel' : ''), role: 'row', tabindex: '0', style: { top: i * ROWH + 'px', gridTemplateColumns: grid, minWidth: cfg.minWidth || '0', height: ROWH + 'px' }, 'aria-selected': String(!!sel),
        onclick: () => cfg.onSelect && cfg.onSelect(r), onkeydown: ev => { if (ev.key === 'Enter') cfg.onSelect && cfg.onSelect(r); } });
      for (const c of cfg.cols) { const cell = h('div', { role: 'cell', class: c.cls || '' }); const v = c.render(r); if (v instanceof Node) cell.appendChild(v); else cell.textContent = v === undefined || v === null ? '' : String(v); row.appendChild(cell); }
      body.appendChild(row);
    }
  }
  wrap.addEventListener('scroll', () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; paint(); }); });
  new ResizeObserver(() => { if (wrap.isConnected) paint(); }).observe(wrap);
  return { el: wrap, refresh, count, repaint: paint, get rows() { return data; } };
}
function toolsRow(...kids) { return h('div', { class: 'tools' }, ...kids); }
function searchBox(ph, onInput) { const i = h('input', { type: 'text', placeholder: ph, 'aria-label': ph, oninput: () => onInput(i.value) }); return i; }
function selectBox(label, opts, onChange) {
  const sel = h('select', { 'aria-label': label, onchange: () => onChange(sel.value) }, ...opts.map(([v, t]) => h('option', { value: v }, t)));
  return sel;
}
function procLink(id) {
  if (!P.has(id)) return h('span', { class: 'muted' }, 'unattributed');
  return h('span', { class: 'proc-link', title: 'Open process', onclick: ev => { ev.stopPropagation(); setState({ sel: { type: 'proc', id } }); } }, pLabel(id));
}
function kindCell(e) { const kk = KINDS.find(z => z.id === groupOf(e)); return h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '7px' } }, s('svg', { width: 11, height: 11, viewBox: '0 0 11 11', 'aria-hidden': 'true' }, marker(kk.shape, 5.5, 5.5, 3.6, KC[kk.id])), e.kind === 'exit' ? 'exit' : e.kind === 'udp' ? 'udp' : kk.label); }
function exitCell(p) {
  if (!p.exit) return h('span', { class: 'muted' }, 'not recorded');
  if (p.exit.signal) return h('span', { class: 'sev sev-high' }, icon('x', 12), p.exit.signal_name);
  return p.exit.code === 0 ? h('span', { class: 'muted' }, '0') : h('span', { class: 'sev sev-medium' }, icon('warn', 12), 'exit ' + p.exit.code);
}

/* ===== virtualised, sortable table. rows() is re-evaluated on refresh() so filters always apply. ===== */
const PRINT_ROWS = 4000;
function vtable(cfg) {
  cfg = { ...cfg, cols: cfg.cols.filter(c => !(cfg.dropCols || []).includes(c.key)) };
  const ROWH = matchMedia('(pointer: coarse)').matches ? Math.max(cfg.rowHeight || 32, 40) : (cfg.rowHeight || 32);
  let sortKey = cfg.defaultSort || null, sortDir = cfg.defaultDir || 1, data = [], raf = 0;
  const grid = cfg.cols.map(c => c.w || '1fr').join(' ');
  const head = h('div', { class: 'tbl-head', style: { gridTemplateColumns: grid, minWidth: cfg.minWidth || '0' }, role: 'row' });
  const body = h('div', { class: 'tbl-body', role: 'rowgroup' });
  const emptyCell = h('div', { role: 'cell' });
  const empty = h('div', { role: 'row', style: { display: 'none' } }, emptyCell);   // an empty table still needs a row to be a valid table
  const wrap = h('div', { class: 'tbl-wrap', style: { flex: '1', minHeight: '160px', maxHeight: cfg.maxHeight || 'none' }, role: 'table', 'aria-label': cfg.label || 'table' }, head, body, empty);
  const count = h('span', { class: 'muted num' });
  for (const c of cfg.cols) {
    head.appendChild(h('div', { class: 'th', role: 'columnheader', 'aria-sort': 'none' }, h('button', { type: 'button', title: c.sort ? 'Sort by ' + c.label : c.label, onclick: () => { if (!c.sort) return; if (sortKey === c.key) sortDir = -sortDir; else { sortKey = c.key; sortDir = 1; } refresh(); } }, c.label + (sortKey === c.key ? (sortDir > 0 ? ' ▲' : ' ▼') : ''))));
  }
  function refresh() {
    data = cfg.rows().slice();
    const col = cfg.cols.find(c => c.key === sortKey);
    if (col && col.sort) data.sort((a, b) => { const x = col.sort(a), y = col.sort(b); return (x < y ? -1 : x > y ? 1 : 0) * sortDir; });
    $$('.th', head).forEach((th, i) => { const c = cfg.cols[i]; $('button', th).textContent = c.label + (sortKey === c.key ? (sortDir > 0 ? ' ▲' : ' ▼') : ''); th.setAttribute('aria-sort', sortKey === c.key ? (sortDir > 0 ? 'ascending' : 'descending') : 'none'); });
    body.style.height = data.length * ROWH + 'px'; empty.style.display = data.length ? 'none' : 'block';
    if (!data.length) {   // say WHY it is empty: nothing recorded, or the user's own filter excluded everything
      clear(emptyCell);
      if (S.q || S.range) emptyCell.appendChild(emptyState('search', S.q ? 'No matches for “' + short(S.q, 40) + '”' : 'Nothing in the selected time range', 'Your ' + (S.q ? 'search' : 'time range') + ' is hiding every row.', h('button', { class: 'btn', type: 'button', onclick: () => { const i = $('#search'); if (i) i.value = ''; setState({ q: '', range: null }); } }, 'Clear search and time range')));
      else emptyCell.appendChild(emptyState('info', cfg.empty || 'Nothing to show', 'The recorder did not capture anything of this kind in this run.'));
    }
    count.textContent = fmtN(data.length) + ' row' + (data.length === 1 ? '' : 's');
    if (cfg.onCount) cfg.onCount(data.length);
    paint();
  }
  function paint() {
    const keep = body.contains(document.activeElement) && document.activeElement.dataset ? document.activeElement.dataset.i : null;
    const top = wrap.scrollTop, vh = wrap.clientHeight || 400;
    // on paper every row is rendered (up to a cap): a virtualised window would print only what happens to be on screen
    const i0 = PRINTING ? 0 : Math.max(0, Math.floor(top / ROWH) - 6), i1 = PRINTING ? Math.min(data.length, PRINT_ROWS) : Math.min(data.length, Math.ceil((top + vh) / ROWH) + 6);
    clear(body);
    body.style.height = (PRINTING ? Math.min(data.length, PRINT_ROWS) : data.length) * ROWH + (PRINTING && data.length > PRINT_ROWS ? ROWH : 0) + 'px';
    if (PRINTING && data.length > PRINT_ROWS) body.appendChild(h('div', { class: 'tbl-row muted', style: { top: PRINT_ROWS * ROWH + 'px', height: ROWH + 'px', display: 'block', padding: '6px 12px' } }, 'Printed: the first ' + fmtN(PRINT_ROWS) + ' of ' + fmtN(data.length) + ' rows. Use the Markdown report for everything.'));
    for (let i = i0; i < i1; i++) {
      const r = data[i], sel = cfg.isSelected && cfg.isSelected(r);
      const row = h('div', { class: 'tbl-row' + (sel ? ' sel' : ''), role: 'row', tabindex: '0', style: { top: i * ROWH + 'px', gridTemplateColumns: grid, minWidth: cfg.minWidth || '0', height: ROWH + 'px' }, 'aria-selected': String(!!sel),
        onclick: () => cfg.onSelect && cfg.onSelect(r), onkeydown: ev => { if (ev.key === 'Enter') { ev.preventDefault(); cfg.onSelect && cfg.onSelect(r); } } });
      row.dataset.i = i; row.dataset.fk = 'r:' + cfg.label + ':' + i;
      for (const c of cfg.cols) { const cell = h('div', { role: 'cell', class: c.cls || '' }); const v = c.render(r); if (v instanceof Node) cell.appendChild(v); else { cell.textContent = v === undefined || v === null ? '' : String(v); if (cell.textContent.length > 18) cell.title = cell.textContent; } row.appendChild(cell); }
      body.appendChild(row);
    }
    if (keep !== null) { const el = body.querySelector('[data-i="' + keep + '"]'); if (el) el.focus({ preventScroll: true }); }
  }
  wrap.addEventListener('keydown', ev => {
    const row = ev.target.closest && ev.target.closest('.tbl-row'); if (!row) return;
    const i = +row.dataset.i, move = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10, Home: -1e9, End: 1e9 }[ev.key]; if (!move) return;
    ev.preventDefault(); const j = Math.max(0, Math.min(data.length - 1, i + move));
    if (j * ROWH < wrap.scrollTop || (j + 2) * ROWH > wrap.scrollTop + wrap.clientHeight) wrap.scrollTop = Math.max(0, j * ROWH - wrap.clientHeight / 2);
    paint(); const el = body.querySelector('[data-i="' + j + '"]'); if (el) el.focus();
  });
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
function kindCell(e) { const kk = KINDS.find(z => z.id === groupOf(e)); return h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '7px' } }, s('svg', { width: 11, height: 11, viewBox: '0 0 11 11', 'aria-hidden': 'true' }, marker(kk.shape, 5.5, 5.5, 3.6, KC[kk.id])), e.kind === 'exit' ? 'Exit' : e.kind === 'udp' ? 'UDP' : kk.label); }
function exitCell(p) {
  if (!p.exit) return h('span', { class: 'muted' }, 'not recorded');
  if (p.exit.signal) return h('span', { class: 'sev sev-high' }, icon('x', 12), p.exit.signal_name);
  return p.exit.code === 0 ? h('span', { class: 'muted' }, '0') : h('span', { class: 'sev sev-medium' }, icon('warn', 12), 'exit ' + p.exit.code);
}

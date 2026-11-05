/* ===== shell, tabs, router, global search ===== */
const TABS = [
  ['overview', 'Overview', 'overview', overviewView], ['tree', 'Process tree', 'tree', treeView], ['timeline', 'Timeline', 'timeline', timelineView],
  ['network', 'Network', 'network', networkView], ['http', 'HTTP', 'http', httpView], ['dns', 'DNS', 'dns', dnsView], ['commands', 'Commands', 'commands', commandsView],
  ['files', 'Files', 'files', filesView], ['events', 'Events', 'events', eventsView], ['findings', 'Findings', 'findings', findingsView], ['run', 'Run', 'run', runView],
];
function logo() {
  return s('svg', { viewBox: '0 0 32 32', width: 30, height: 30, 'aria-hidden': 'true' },
    s('circle', { cx: 16, cy: 16, r: 13, fill: 'none', stroke: cssv('--brand'), 'stroke-width': 1.6, opacity: 0.35 }), s('circle', { cx: 16, cy: 16, r: 8.5, fill: 'none', stroke: cssv('--brand'), 'stroke-width': 1.6, opacity: 0.65 }),
    s('path', { d: 'M16 16 L27 9', stroke: cssv('--brand'), 'stroke-width': 2, 'stroke-linecap': 'round' }), s('circle', { cx: 16, cy: 16, r: 2.6, fill: cssv('--brand') }), s('circle', { cx: 24, cy: 19, r: 1.8, fill: '#fff' }));
}
function buildShell() {
  const app = h('div', { id: 'app' });
  const [vcss, vicon, vlabel] = verdictOf();
  const search = h('input', { id: 'search', type: 'search', placeholder: 'Search commands, hosts, paths…   /', 'aria-label': 'Search everything', autocomplete: 'off', spellcheck: 'false' });
  let timer = 0;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => setState({ q: search.value.trim() }), 110); });
  const top = h('header', { id: 'top' },
    h('div', { class: 'brand' }, logo()),
    h('div', { class: 'wordmark' }, 'TRACEWATCH', h('small', null, 'PROCESS FLIGHT RECORDER')),
    h('div', { class: 'runline' }, h('div', { class: 'runcmd', title: DATA.run.cmdline }, h('b', null, '$'), oneLine(DATA.run.cmdline)), h('span', { class: 'chip num' }, fmtT(DATA.run.duration_ns)), h('span', { class: 'chip' }, DATA.run.id)),
    h('span', { class: 'verdict v-' + DATA.run.verdict, title: (DATA.run.reasons || []).join('; ') || vlabel }, icon(vicon, 15), vlabel.toUpperCase()), search);
  const rail = h('nav', { id: 'rail', role: 'tablist', 'aria-label': 'Report sections' });
  const main = h('main', { id: 'main' });
  const views = {};
  const high = DATA.findings.filter(f => f.severity === 'high').length, med = DATA.findings.filter(f => f.severity === 'medium').length;
  const direct = DATA.destinations.filter(d => d.via === 'direct' && !d.loopback).length;
  for (const [id, label, ic, make] of TABS) {
    const badge = id === 'findings' && (high + med) ? h('span', { class: 'badge', style: { background: high ? SEVC.high : SEVC.medium } }, String(high + med))
      : id === 'network' && direct ? h('span', { class: 'badge', style: { background: SEVC.medium } }, String(direct)) : null;
    rail.appendChild(h('button', { class: 'tab', role: 'tab', type: 'button', 'data-tab': id, 'aria-selected': 'false', 'aria-controls': 'view-' + id, onclick: () => setState({ tab: id }) }, icon(ic, 21), label, badge));
    const v = make(); views[id] = v; main.appendChild(v);
  }
  add(app, [top, rail, main]);
  document.body.appendChild(app); document.body.appendChild(drawerEl); document.body.appendChild(tipEl);
  return { views, search };
}
function init() {
  const { views, search } = buildShell();
  const fromHash = () => {
    const [tab, a, b] = location.hash.replace(/^#\/?/, '').split('/'); const patch = {};
    if (TABS.some(t => t[0] === tab)) patch.tab = tab;
    if (a === 'proc' && P.has(b)) patch.sel = { type: 'proc', id: b }; else if (a === 'finding' && FD.has(b)) patch.sel = { type: 'finding', id: b }; else if (a === 'http' && HX.has(b)) patch.sel = { type: 'http', id: b };
    Object.assign(S, patch);
  };
  fromHash();
  let shown = null;
  const sync = () => {
    $$('.tab').forEach(t => t.setAttribute('aria-selected', String(t.dataset.tab === S.tab)));
    if (shown !== S.tab) { for (const [id, v] of Object.entries(views)) v.classList.toggle('on', id === S.tab); shown = S.tab; const v = views[S.tab]; if (v.onShow) requestAnimationFrame(() => v.onShow()); }
    syncDrawer();
    const sel = S.sel && ['proc', 'finding', 'http'].includes(S.sel.type) ? '/' + S.sel.type + '/' + S.sel.id : '';
    try { history.replaceState(null, '', '#/' + S.tab + sel); } catch (e) { /* file:// in some browsers */ }
    if (S.tab === 'tree' && S.sel && S.sel.type === 'proc' && views.tree.reveal && views.tree.classList.contains('on')) views.tree.reveal(S.sel.id);
  };
  onState(sync); sync();
  addEventListener('hashchange', () => { fromHash(); setState({}); });
  addEventListener('keydown', ev => {
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (ev.key === '/' && !typing) { ev.preventDefault(); search.focus(); search.select(); }
    else if (ev.key === 'Escape') {
      if (typing && search.value) { search.value = ''; setState({ q: '' }); } else if (S.sel) closeDrawer(); else if (S.range) setState({ range: null });
      if (typing) document.activeElement.blur();
    }
  });
  window.__tw_ready = true;
}
init();

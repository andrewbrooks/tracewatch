/* ===== shell, tabs, router, global search ===== */
const TABS = [
  ['overview', 'Overview', 'overview', overviewView], ['tree', 'Process tree', 'tree', treeView], ['timeline', 'Timeline', 'timeline', timelineView],
  ['network', 'Network', 'network', networkView], ['http', 'HTTP', 'http', httpView], ['dns', 'DNS', 'dns', dnsView], ['commands', 'Commands', 'commands', commandsView],
  ['files', 'Files', 'files', filesView], ['events', 'Events', 'events', eventsView], ['findings', 'Findings', 'findings', findingsView], ['run', 'Run', 'run', runView],
];
function logo() {   // brand parts use currentColor (.brand { color: var(--brand) }) so the logo follows the theme
  return s('svg', { viewBox: '0 0 32 32', width: 30, height: 30, 'aria-hidden': 'true', style: { color: 'var(--brand)' } },
    s('circle', { cx: 16, cy: 16, r: 13, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, opacity: 0.35 }), s('circle', { cx: 16, cy: 16, r: 8.5, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, opacity: 0.65 }),
    s('path', { d: 'M16 16 L27 9', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round' }), s('circle', { cx: 16, cy: 16, r: 2.6, fill: 'currentColor' }), s('circle', { cx: 24, cy: 19, r: 1.8, style: { fill: 'var(--text)' } }));
}
function helpModal() {
  const rows = [['/', 'Focus the search box'], ['Esc', 'Close the drawer, clear the search, or reset the time range'], ['1 – 9, 0', 'Jump to a view (Overview … Run)'], ['?', 'Show or hide this help'],
    ['Tab / Shift+Tab', 'Move between controls'], ['Enter', 'Open the selected row, node or finding'], ['↑ ↓ PgUp PgDn Home End', 'Move through table rows'], ['← → ↑ ↓', 'Move through the process tree (→ expands, ← collapses)'], ['Drag · wheel · pinch', 'Pan and zoom the process tree']];
  const bg = h('div', { class: 'modal-bg', id: 'help', onclick: ev => { if (ev.target === bg) toggleHelp(false); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Keyboard shortcuts' }, h('h3', null, 'Keyboard shortcuts'),
      h('div', { class: 'kv' }, ...rows.flatMap(([k, d]) => [h('div', { class: 'k2' }, h('kbd', null, k)), h('div', { class: 'v2' }, d)])),
      h('div', { style: { marginTop: '14px', display: 'flex', justifyContent: 'flex-end' } }, h('button', { class: 'btn', type: 'button', onclick: () => toggleHelp(false) }, 'Close'))));
  return bg;
}
function toggleHelp(force) { const m = $('#help'), on = force === undefined ? !m.classList.contains('on') : force; m.classList.toggle('on', on); if (on) $('.btn', m).focus(); }
function cycleTheme() {
  themePref = { auto: 'light', light: 'dark', dark: 'auto' }[themePref];
  try { localStorage.setItem(THEME_KEY, themePref); } catch (e) { /* storage blocked: the choice lasts for this page only */ }
  applyTheme(); paintThemeBtn(); setState({});
}
const themeBtn = h('button', { class: 'iconbtn', id: 'themebtn', type: 'button', onclick: cycleTheme });
function paintThemeBtn() {
  const next = { auto: 'light', light: 'dark', dark: 'auto' }[themePref];
  clear(themeBtn).appendChild(icon(themePref === 'light' ? 'sun' : themePref === 'dark' ? 'moon' : 'auto', 17));
  themeBtn.setAttribute('aria-label', `Theme: ${themePref}. Switch to ${next}.`);
  themeBtn.title = themePref === 'auto' ? 'Theme: follows your system. Click for light.' : `Theme: ${themePref}. Click for ${next}.`;
}
lightMQ.addEventListener('change', () => { if (themePref === 'auto') { applyTheme(); setState({}); } });
let VIEWS = {};   // set by init(): print shows EVERY view, and a view that was never opened has not been filled yet
printMQ.addEventListener('change', ev => { PRINTING = ev.matches; applyTheme(); setState({}); for (const v of Object.values(VIEWS)) if (v.onShow) requestAnimationFrame(() => v.onShow()); });

function buildShell() {
  const app = h('div', { id: 'app' });
  const [vcss, vicon, vlabel] = verdictOf();
  const search = h('input', { id: 'search', type: 'search', placeholder: 'Search commands, hosts, paths…   /', 'aria-label': 'Search everything', autocomplete: 'off', spellcheck: 'false' });
  let timer = 0;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => setState({ q: search.value.trim() }), 110); });
  const top = h('header', { id: 'top' },
    h('div', { class: 'brand' }, logo()),
    h('div', { class: 'wordmark' }, 'TRACEWATCH', h('small', null, 'PROCESS FLIGHT RECORDER')),
    h('div', { class: 'runline' }, h('div', { class: 'runcmd', role: 'button', tabindex: '0', title: DATA.run.cmdline + '\n(click to copy)', onclick: () => copyText(DATA.run.cmdline, 'Command'), onkeydown: ev => { if (ev.key === 'Enter') copyText(DATA.run.cmdline, 'Command'); } }, h('b', null, '$'), oneLine(DATA.run.cmdline)), h('span', { class: 'chip num' }, fmtT(DATA.run.duration_ns)), h('span', { class: 'chip' }, DATA.run.id)),
    h('button', { class: 'verdict ' + verdictClass(), type: 'button', title: ((DATA.run.reasons || []).join('; ') || vlabel) + ' (open the integrity details)', onclick: () => setState({ tab: 'run' }) }, icon(vicon, 15), vlabel.toUpperCase()), search, themeBtn, h('button', { class: 'iconbtn', type: 'button', 'aria-label': 'Keyboard shortcuts', title: 'Keyboard shortcuts (?)', onclick: () => toggleHelp() }, '?'));
  paintThemeBtn();
  const rail = h('nav', { id: 'rail', role: 'tablist', 'aria-label': 'Report sections' });
  const main = h('main', { id: 'main', tabindex: '-1' });
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
  document.body.appendChild(h('a', { class: 'skip', href: '#main', onclick: ev => { ev.preventDefault(); main.focus(); } }, 'Skip to content'));
  document.body.appendChild(app); document.body.appendChild(drawerEl); document.body.appendChild(tipEl); document.body.appendChild(toastEl); document.body.appendChild(helpModal());
  return { views, search };
}
function init() {
  const { views, search } = buildShell();
  VIEWS = views;
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
    if (shown !== S.tab) {
      for (const [id, v] of Object.entries(views)) v.classList.toggle('on', id === S.tab); shown = S.tab; const v = views[S.tab];
      $('#main').scrollTop = 0; document.title = (TABS.find(t => t[0] === S.tab) || [0, ''])[1] + ' · ' + short(oneLine(DATA.run.cmdline), 60) + ' · tracewatch';
      if (v.onShow) requestAnimationFrame(() => v.onShow());
    }
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
    else if (ev.key === '?' && !typing) { ev.preventDefault(); toggleHelp(); }
    else if (!typing && !ev.metaKey && !ev.ctrlKey && !ev.altKey && /^[0-9]$/.test(ev.key)) { const t = TABS[(+ev.key + 9) % 10]; if (t) { ev.preventDefault(); setState({ tab: t[0] }); } }
    else if (ev.key === 'Escape') {
      if ($('.modal-bg.on')) toggleHelp(false); else if (typing && search.value) { search.value = ''; setState({ q: '' }); } else if (S.sel) closeDrawer(); else if (S.range) setState({ range: null });
      if (typing) document.activeElement.blur();
    }
  });
  window.__tw_ready = true;
}
init();

/* ===== shell, tabs, router, global search ===== */
// the order is the story: the answer (Findings) right after the summary, then what ran, then the network, then files, then how it was recorded
const TABS = [
  ['overview', 'Overview', 'overview', overviewView], ['findings', 'Findings', 'findings', findingsView],
  ['tree', 'Process tree', 'tree', treeView], ['timeline', 'Timeline', 'timeline', timelineView], ['commands', 'Commands', 'commands', commandsView], ['events', 'Events', 'events', eventsView],
  ['network', 'Network', 'network', networkView], ['http', 'HTTP', 'http', httpView], ['dns', 'DNS', 'dns', dnsView],
  ['files', 'Files', 'files', filesView], ['run', 'Run', 'run', runView],
];
const NAV_GROUP_END = new Set(['findings', 'events', 'dns', 'files']);   // a divider after each group in the rail
const NAV_PRIMARY = new Set(['overview', 'findings', 'tree', 'http']);   // phones show these four plus a More menu
function logo() {   // brand parts use currentColor (.brand { color: var(--brand) }) so the logo follows the theme
  return s('svg', { viewBox: '0 0 32 32', width: 30, height: 30, 'aria-hidden': 'true', style: { color: 'var(--brand)' } },
    s('circle', { cx: 16, cy: 16, r: 13, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, opacity: 0.35 }), s('circle', { cx: 16, cy: 16, r: 8.5, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, opacity: 0.65 }),
    s('path', { d: 'M16 16 L27 9', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round' }), s('circle', { cx: 16, cy: 16, r: 2.6, fill: 'currentColor' }), s('circle', { cx: 24, cy: 19, r: 1.8, style: { fill: 'var(--text)' } }));
}
function helpModal() {
  const rows = [['/', 'Focus the search box'], ['Esc', 'Close the drawer, clear the search, or reset the time range'], ['1 – 9, 0', 'Jump to a view, in the order of the side bar (Overview, Findings, Process tree …; Run has no key)'], ['?', 'Show or hide this help'],
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
printMQ.addEventListener('change', ev => { PRINTING = ev.matches; applyTheme(); setState({});
  // findings print expanded: open every rule disclosure for paper, and put back the ones that were closed afterwards
  const syncDetails = () => $$('details.about-rule, details.refrules').forEach(d => { if (PRINTING) { if (d.dataset.wasClosed === undefined) d.dataset.wasClosed = d.open ? '' : '1'; d.open = true; } else if (d.dataset.wasClosed !== undefined) { if (d.dataset.wasClosed) d.open = false; delete d.dataset.wasClosed; } });
  for (const v of Object.values(VIEWS)) if (v.onShow) requestAnimationFrame(() => v.onShow());
  syncDetails(); requestAnimationFrame(() => requestAnimationFrame(syncDetails));   // the views are redrawn on the next frames: catch the disclosures they create
});

function toggleCmd(force) {   // the command is the run's identity: show all of it, wrapped, with a copy button
  let p = $('#cmdfull');
  if (!p) {
    p = h('div', { id: 'cmdfull', class: 'cmdfull', role: 'region', 'aria-label': 'Full command' }, h('div', { class: 'mono cmdtext' }, DATA.run.cmdline),
      h('div', { class: 'cmdbar' }, h('span', { class: 'muted' }, 'cwd ' + (DATA.run.cwd || '?')), h('span', { class: 'sp' }), h('button', { class: 'btn', type: 'button', onclick: () => copyText(DATA.run.cmdline, 'Command') }, 'Copy'), h('button', { class: 'btn', type: 'button', onclick: () => toggleCmd(false) }, 'Close')));
    document.body.appendChild(p);
  }
  const on = force === undefined ? !p.classList.contains('on') : force;
  p.classList.toggle('on', on); const rc = $('.runcmd'); if (rc) rc.setAttribute('aria-expanded', String(on));
  if (on) p.style.top = ($('#top').getBoundingClientRect().bottom + 6) + 'px';
}
function toggleMore(force) {
  const m = $('#morepanel'), on = force === undefined ? !m.classList.contains('on') : force;
  m.classList.toggle('on', on); const b = $('.tab.more'); if (b) b.setAttribute('aria-expanded', String(on));
}
function buildShell() {
  const app = h('div', { id: 'app' });
  const [vcss, vicon, vlabel] = verdictOf();
  const search = h('input', { id: 'search', type: 'search', placeholder: 'Search commands, hosts, paths…   /', 'aria-label': 'Search everything', autocomplete: 'off', spellcheck: 'false' });
  let timer = 0;
  search.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => setState({ q: search.value.trim() }), 110); });
  const top = h('header', { id: 'top' },
    h('h1', { class: 'sr' }, 'tracewatch report: ' + short(oneLine(DATA.run.cmdline), 70)),
    h('div', { class: 'brand' }, logo()),
    h('div', { class: 'wordmark' }, 'TRACEWATCH', h('small', null, 'PROCESS FLIGHT RECORDER')),
    h('div', { class: 'runline' }, h('div', { class: 'runcmd', role: 'button', tabindex: '0', 'aria-expanded': 'false', title: 'Click to see the whole command', onclick: () => toggleCmd(), onkeydown: ev => { if (ev.key === 'Enter') { ev.preventDefault(); toggleCmd(); } } }, h('b', null, '$'), oneLine(DATA.run.cmdline)), h('button', { class: 'iconbtn copycmd', type: 'button', 'aria-label': 'Copy the command', title: 'Copy the command', onclick: () => copyText(DATA.run.cmdline, 'Command') }, icon('copy', 15)), h('span', { class: 'chip num' }, fmtT(DATA.run.duration_ns)), h('span', { class: 'chip' }, DATA.run.id)),
    h('button', { class: 'verdict ' + verdictClass(), type: 'button', title: ((DATA.run.reasons || []).join('; ') || vlabel) + ' (open the integrity details)', onclick: () => setState({ tab: 'run' }) }, icon(vicon, 15), vlabel.toUpperCase()), search, themeBtn, h('button', { class: 'iconbtn', type: 'button', 'aria-label': 'Keyboard shortcuts', title: 'Keyboard shortcuts (?)', onclick: () => toggleHelp() }, '?'));
  paintThemeBtn();
  const rail = h('div', { id: 'rail' });   // the landmark is the <nav> around it: these are links between views, not a tab widget
  const railNav = h('nav', { 'aria-label': 'Report sections', style: { display: 'contents' } }, rail);   // a real navigation landmark; the tab list inside keeps its own role
  const main = h('main', { id: 'main', tabindex: '-1' });
  const views = {};
  const high = DATA.findings.filter(f => f.severity === 'high').length, med = DATA.findings.filter(f => f.severity === 'medium').length;
  const direct = DATA.destinations.filter(d => d.via === 'direct' && !d.loopback).length;
  for (const [id, label, ic, make] of TABS) {
    const badge = id === 'findings' && (high + med) ? h('span', { class: 'badge', style: { background: high ? SEVC.high : SEVC.medium, color: high ? '#ffffff' : '' } }, String(high + med))
      : id === 'network' && direct ? h('span', { class: 'badge', style: { background: SEVC.medium } }, String(direct)) : null;
    const why = id === 'findings' && (high + med) ? high + ' high and ' + med + ' medium findings (' + DATA.findings.length + ' in all, including low and info)' : id === 'network' && direct ? plural(direct, 'destination') + ' reached without the proxy' : '';
    rail.appendChild(h('button', { class: 'tab' + (NAV_PRIMARY.has(id) ? '' : ' secondary'), type: 'button', 'data-tab': id, title: why || undefined, 'aria-label': why ? label + ' ' + (id === 'findings' ? high + med : direct) + ': ' + why : undefined, onclick: () => setState({ tab: id }) }, icon(ic, 21), label, badge ? ' ' : null, badge));
    if (NAV_GROUP_END.has(id)) rail.appendChild(h('div', { class: 'tab-sep', 'aria-hidden': 'true' }));
    const v = make(); views[id] = v; main.appendChild(v);
  }
  rail.appendChild(h('button', { class: 'tab more', type: 'button', 'aria-haspopup': 'true', 'aria-expanded': 'false', onclick: () => toggleMore() }, icon('more', 21), 'More'));
  document.body.appendChild(h('div', { id: 'morepanel', class: 'morepanel', role: 'group', 'aria-label': 'More sections' }, ...TABS.filter(t => !NAV_PRIMARY.has(t[0])).map(([id, label, ic]) => h('button', { class: 'moretab', type: 'button', 'data-tab': id, onclick: () => { toggleMore(false); setState({ tab: id }); } }, icon(ic, 18), label))));
  add(app, [top, railNav, main]);
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
    $$('.tab[data-tab], .moretab').forEach(t => { if (t.dataset.tab === S.tab) t.setAttribute('aria-current', 'page'); else t.removeAttribute('aria-current'); });
    { const mb = $('.tab.more'); if (mb) { if (!NAV_PRIMARY.has(S.tab)) mb.setAttribute('aria-current', 'true'); else mb.removeAttribute('aria-current'); } }
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
      if ($('#cmdfull.on')) toggleCmd(false); else if ($('#morepanel.on')) toggleMore(false); else if ($('.modal-bg.on')) toggleHelp(false); else if (typing && search.value) { search.value = ''; setState({ q: '' }); } else if (S.sel) closeDrawer(); else if (S.range) setState({ range: null });
      if (typing) document.activeElement.blur();
    }
  });
  window.__tw_ready = true;
}
init();

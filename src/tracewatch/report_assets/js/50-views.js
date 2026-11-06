/* ===== views ===== */
const VC = { complete: ['--good', 'check', 'Recording complete'], 'complete-with-losses': ['--warning', 'warn', 'Complete, with losses'], incomplete: ['--critical', 'x', 'Recording incomplete'], 'in-progress': ['--warning', 'warn', 'Recording in progress'], unreadable: ['--critical', 'x', 'Unreadable'] };
const VC_EMPTY = ['--sev-info', 'info', 'No activity recorded'];
// An empty recording is not a success: nothing was observed (the command may have failed to start). Broken states still win.
const verdictOf = () => (isEmptyRun() && !['incomplete', 'unreadable', 'in-progress'].includes(DATA.run.verdict)) ? VC_EMPTY : (VC[DATA.run.verdict] || VC.unreadable);
const verdictClass = () => (verdictOf() === VC_EMPTY ? 'v-empty' : 'v-' + DATA.run.verdict);
const viewShell = (id, title, sub, ...kids) => h('div', { class: 'view', id: 'view-' + id }, h('h2', { class: 'vt' }, title), sub ? h('p', { class: 'vsub' }, sub) : null, ...kids);
const countBy = (arr, f) => { const m = new Map(); for (const x of arr) { const k = f(x); m.set(k, (m.get(k) || 0) + 1); } return m; };

function overviewView() {
  const [vcss, vicon, vlabel] = verdictOf(), st = DATA.stats, fc = st.findings, direct = DATA.destinations.filter(d => d.via === 'direct' && !d.loopback);
  const banner = h('div', { class: 'card banner', style: { '--vc': 'var(' + vcss + ')', '--vct': 'var(' + vcss.replace('--', '--t-') + ')' } }, h('div', { class: 'vi' }, icon(vicon, 38)),
    h('div', null, h('h2', null, vlabel), h('div', { class: 'muted' }, 'Run ' + DATA.run.id + ' · ' + fmtWall(DATA.run.started_wall_ns) + ' · ' + fmtT(DATA.run.duration_ns) + ' · target ' + ((DATA.run.root_exit || {}).status || 'exit not recorded')),
      (() => {   // lead with the answer: what did this do, and is it worth a closer look?
        const hi = DATA.findings.filter(f => f.severity === 'high'), bits = [plural(st.processes, 'process', 'processes'), 'contacted ' + plural(st.destinations, 'destination') + (direct.length ? ' (' + direct.length + ' bypassed the proxy)' : ''), 'made ' + plural(st.http, 'HTTP request'), 'touched ' + plural(st.files, 'watched file')];
        const sent = 'Ran ' + bits[0] + ', ' + bits.slice(1).join(', ') + '. ' + (hi.length ? plural(hi.length, 'high-severity finding') + (fc.medium ? ' and ' + fmtN(fc.medium) + ' medium' : '') + '.' : (fc.medium ? 'No high-severity findings; ' + fmtN(fc.medium) + ' medium.' : 'No high or medium findings.'));
        return h('div', { class: 'glance' }, h('p', null, isEmptyRun() ? 'Nothing was recorded.' : sent),
          hi.length ? h('ul', { class: 'glance-list' }, hi.slice(0, 3).map(f => h('li', null, h('button', { type: 'button', class: 'glance-link', onclick: () => setState({ sel: { type: 'finding', id: f.id } }) }, icon('x', 13), short(f.title, 110)))), hi.length > 3 ? h('li', null, h('button', { type: 'button', class: 'glance-link more', onclick: () => setState({ tab: 'findings' }) }, '+' + (hi.length - 3) + ' more high-severity findings')) : null) : null);
      })(),
      (() => {
        const lines = [...DATA.run.reasons];
        if (isEmptyRun()) lines.unshift('The recorder saw no process or network activity. If the command failed to start, its exit status is the place to look.');
        if (DATA.integrity.untrusted_after_mono) lines.push('Nothing after ' + fmtAt(untrustedAt()) + ' can be trusted: the recorder had already died (hatched in the charts below).');
        return lines.length ? h('ul', null, lines.map(r => h('li', null, r))) : null;
      })()));
  const tile = (label, value, sub, glow, go) => h('div', { class: 'card kpi', style: { '--glow': glow, cursor: go ? 'pointer' : 'default' }, onclick: go, role: go ? 'button' : undefined, tabindex: go ? '0' : undefined, onkeydown: go ? (ev => { if (ev.key === 'Enter') go(); }) : undefined }, h('div', { class: 'l' }, label), h('div', { class: 'v num' }, value), h('div', { class: 's' }, sub));
  const tab = t => () => setState({ tab: t });
  const sevPips = ['high', 'medium', 'low'].filter(k => fc[k]).map(k => h('span', { class: 'sev sev-' + k }, icon(SEVICON[k], 11), String(fc[k])));
  const kpis = h('div', { class: 'kpis' },
    tile('Findings', fmtN(DATA.findings.length), sevPips.length ? [...sevPips.slice(0, 3), fc.info ? h('span', { class: 'muted' }, '+' + fmtN(fc.info) + ' info') : null] : 'none fired', 'rgba(208,59,59,.16)', tab('findings')),
    tile('Processes', fmtN(st.processes), 'depth ' + st.max_depth + ' · ' + plural(st.commands, 'command'), 'rgba(57,135,229,.16)', tab('tree')),
    tile('Destinations', fmtN(st.destinations), direct.length ? h('span', { class: 'sev sev-medium' }, icon('warn', 11), direct.length + ' direct') : (st.destinations ? 'all via proxy' : 'none recorded'), 'rgba(25,158,112,.16)', tab('network')),
    tile('HTTP requests', fmtN(st.http), plural(DATA.http.filter(x => x.error || (x.status || 0) >= 400).length, 'error') + ' · ' + plural(st.websockets, 'websocket'), 'rgba(217,89,38,.16)', tab('http')),
    tile('DNS names', fmtN(st.dns_names), plural(DATA.dns.resolver_contacts.length, 'resolver contact'), 'rgba(213,81,129,.16)', tab('dns')),
    tile('Watched files', fmtN(st.files), 'credential & temp paths', 'rgba(201,133,0,.16)', tab('files')));
  const activity = chartCard('Activity over time', () => h('div', null, storyRibbon(), activityLanes()), activityTable, { count: fmtN(st.events) + ' events', cls: 'span2' });
  const dests = DATA.destinations.map((d, i) => ({ d, i })).sort((a, b) => (b.d.via === 'direct') - (a.d.via === 'direct') || b.d.requests - a.d.requests).slice(0, 8)
    .map(({ d, i }) => ({ label: (d.name || d.ip) + ':' + d.port, value: d.requests, sub: d.via === 'direct' ? 'direct: content not recorded' : fmtB(d.bytes_in) + ' received', flag: d.via === 'direct' && !d.loopback, onclick: () => setState({ sel: { type: 'dest', id: i } }) }));
  const destCard = chartCard('Top destinations', () => rankedBars(dests, { empty: 'No network activity recorded' }), () => rankedTable(dests, ['Destination', 'Requests']), { count: fmtN(DATA.destinations.length) });
  const busy = DATA.processes.map(p => ({ p, n: (evByProc.get(p.id) || []).filter(e => e.kind !== 'exit' && !(e.kind === 'udp' && e.detail.probe)).length })).filter(x => x.n).sort((a, b) => b.n - a.n).slice(0, 8)
    .map(({ p, n }) => ({ label: p.name + ' · ' + p.pid, value: n, sev: ['high', 'medium', 'low'].find(k => p.severity === k) || null, sub: short(oneLine(p.cmdline), 120), onclick: () => setState({ sel: { type: 'proc', id: p.id } }) }));
  const busyCard = chartCard('Busiest processes', () => rankedBars(busy), () => rankedTable(busy, ['Process', 'Events']), { count: 'by events' });
  const cov = h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Recording coverage'), h('span', { class: 'sp' }), h('button', { class: 'btn', type: 'button', onclick: tab('run') }, 'Integrity details')), h('div', { class: 'card-b' }, coverageStrip(), h('div', { class: 'muted', style: { marginTop: '8px' } }, (DATA.integrity.gaps || []).length ? 'Hatched bands are periods a component was not recording.' : 'Every recorder component was running for the whole run.')));
  const top = DATA.findings.filter(f => f.severity !== 'info').slice(0, 4);
  const fcard = h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Top findings'), h('span', { class: 'cnt' }, fmtN(DATA.findings.length)), h('span', { class: 'sp' }), h('button', { class: 'btn', type: 'button', onclick: tab('findings') }, 'All findings')),
    h('div', { class: 'card-b' }, top.length ? top.map(f => h('div', { style: { cursor: 'pointer' }, onclick: () => setState({ sel: { type: 'finding', id: f.id } }) }, findingCard(f, true))) : h('div', { class: 'empty' }, 'No medium or high indicators fired.')));
  const root = viewShell('overview', 'Overview', null, banner, kpis, h('div', { class: 'grid', style: { gridTemplateColumns: '1fr' } }, activity), h('div', { class: 'grid g2', style: { marginTop: '14px' } }, destCard, busyCard), h('div', { class: 'grid g2', style: { marginTop: '14px' } }, fcard, cov));
  root.onShow = () => { activity.redraw(); };
  return root;
}

function networkView() {
  const filter = { direct: false };
  const t = vtable({
    label: 'Network destinations', empty: 'No network destinations recorded', minWidth: '860px',
    cols: [
      { key: 'via', label: 'Via', w: '120px', render: d => d.via === 'direct' ? h('span', { class: 'sev sev-medium' }, icon('warn', 11), 'direct') : h('span', { class: 'pill' }, 'proxy'), sort: d => d.via },
      { key: 'dst', label: 'Destination', w: 'minmax(180px,1.6fr)', cls: 'mono cell', render: d => (d.name || d.ip) + (d.name && d.ip && d.name !== d.ip ? '  ' + d.ip : ''), sort: d => d.name || d.ip || '' },
      { key: 'port', label: 'Port', w: '70px', cls: 'num', render: d => d.port, sort: d => d.port },
      { key: 'req', label: 'Count', w: '76px', cls: 'num', render: d => fmtN(d.requests), sort: d => d.requests },
      { key: 'err', label: 'Errors', w: '70px', cls: 'num', render: d => d.errors ? h('span', { class: 'sev sev-medium' }, String(d.errors)) : '0', sort: d => d.errors },
      { key: 'in', label: 'Received', w: '90px', cls: 'num', render: d => d.via === 'proxy' ? fmtB(d.bytes_in) : '—', sort: d => d.bytes_in },
      { key: 'out', label: 'Sent', w: '90px', cls: 'num', render: d => d.via === 'proxy' ? fmtB(d.bytes_out) : '—', sort: d => d.bytes_out },
      { key: 'tls', label: 'TLS', w: '110px', render: d => d.tls ? (d.tls.version + (d.tls.alpn ? ' · ' + d.tls.alpn : '')) : '—' },
      { key: 'p', label: 'Processes', w: 'minmax(120px,1fr)', render: d => d.procs.slice(0, 3).map(pLabel).join(', ') + (d.procs.length > 3 ? ' +' + (d.procs.length - 3) : '') },
      { key: 'first', label: 'First seen', w: '90px', cls: 'num', render: d => fmtAt(d.first_t), sort: d => d.first_t ?? 0 },
    ],
    defaultSort: 'via', defaultDir: 1,   // 'direct' sorts before 'proxy': the unrecorded connections come first
    rows: () => DATA.destinations.filter(d => (!filter.direct || d.via === 'direct') && qmatch(d.name, d.ip, d.port, d.procs.map(pLabel).join(' '))),
    onSelect: d => setState({ sel: { type: 'dest', id: DATA.destinations.indexOf(d) } }), isSelected: d => S.sel && S.sel.type === 'dest' && DATA.destinations[S.sel.id] === d,
  });
  const direct = DATA.destinations.filter(d => d.via === 'direct' && !d.loopback);
  const btn = h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', onclick: () => { filter.direct = !filter.direct; btn.setAttribute('aria-pressed', String(filter.direct)); t.refresh(); } }, 'Direct connections only');
  const root = h('div', { class: 'view col', id: 'view-network' }, h('h2', { class: 'vt' }, 'Network'),
    h('p', { class: 'vsub' }, 'Everything the process connected to. "proxy" destinations were fully recorded; "direct" connections bypassed the recorder\'s proxy, so the kernel saw them but their content was not recorded.'),
    direct.length ? h('div', { class: 'card banner', style: { '--vc': 'var(--serious)', marginBottom: '12px' } }, icon('warn', 30), h('div', null, h('b', null, direct.length + ' direct destination' + (direct.length > 1 ? 's' : '') + ' bypassed the proxy: '), direct.slice(0, 4).map(d => (d.name || d.ip) + ':' + d.port).join(', '))) : null,
    toolsRow(btn, t.count), t.el);
  root.onShow = () => { t.refresh(); }; onState(() => { if (root.classList.contains('on')) t.refresh(); });
  return root;
}

function httpView() {
  const f = { method: '', klass: '', ws: false };
  const methods = [...new Set(DATA.http.map(x => x.method))].sort();
  const oneHost = DATA.http.length > 1 && new Set(DATA.http.map(x => x.host)).size === 1;   // a column that never varies is noise: say it once
  const t = vtable({
    label: 'HTTP requests', empty: 'No HTTP requests recorded', minWidth: '780px',
    cols: [   // ordered by importance: what happened (status, time) stays visible when the drawer narrows the table; path and size give way first
      { key: 't', label: 'At', w: '82px', cls: 'num', render: x => fmtAt(x.t), sort: x => x.t },
      { key: 'm', label: 'Method', w: '74px', render: x => h('span', { class: 'pill' }, x.method), sort: x => x.method },
      { key: 's', label: 'Status', w: '96px', render: x => statusPill(x), sort: x => x.status ?? 0 },
      { key: 'd', label: 'Time', w: '78px', cls: 'num', render: x => x.duration_ms !== null && x.duration_ms !== undefined ? x.duration_ms + ' ms' : '—', sort: x => x.duration_ms ?? -1 },
      { key: 'proc', label: 'Process', w: 'minmax(110px,.8fr)', render: x => x.proc ? procLink(x.proc) : h('span', { class: 'muted' }, 'unattributed'), sort: x => x.proc || '' },
      { key: 'host', label: 'Host', w: 'minmax(110px,.8fr)', cls: 'mono cell', render: x => x.host, sort: x => x.host },
      { key: 'path', label: 'Path', w: 'minmax(160px,1.6fr)', cls: 'mono cell', render: x => (x.scheme === 'http' ? '⚠ http ' : '') + x.path, sort: x => x.path },
      { key: 'size', label: 'Size', w: '80px', cls: 'num', render: x => fmtB((x.resp_body || {}).size), sort: x => (x.resp_body || {}).size || 0 },
    ],
    defaultSort: 't', defaultDir: 1, dropCols: oneHost ? ['host'] : [],
    rows: () => DATA.http.filter(x => inRange(x.t) && (!f.method || x.method === f.method) && (!f.ws || x.websocket) && (!f.klass || (f.klass === 'err' ? (x.error || (x.status || 0) >= 400) : Math.floor((x.status || 0) / 100) === +f.klass)) && qmatch(x.host, x.path, x.method, x.status, x.error, x.proc ? pLabel(x.proc) : '')),
    onSelect: x => setState({ sel: { type: 'http', id: x.id } }), isSelected: x => S.sel && S.sel.type === 'http' && S.sel.id === x.id,
  });
  const tools = toolsRow(selectBox('Method', [['', 'All methods'], ...methods.map(m => [m, m])], v => { f.method = v; t.refresh(); }), selectBox('Status', [['', 'All statuses'], ['2', '2xx success'], ['3', '3xx redirect'], ['4', '4xx client error'], ['5', '5xx server error'], ['err', 'Errors (4xx, 5xx, failed)']], v => { f.klass = v; t.refresh(); }),
    h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', onclick: ev => { f.ws = !f.ws; ev.currentTarget.setAttribute('aria-pressed', String(f.ws)); t.refresh(); } }, 'WebSockets only'), t.count);
  const root = h('div', { class: 'view col', id: 'view-http' }, h('h2', { class: 'vt' }, 'HTTP requests'), h('p', { class: 'vsub' }, 'Decrypted requests and responses seen by the proxy, attributed to the process that made them. Secrets are redacted before they are written. Click a row for headers, bodies, timing and TLS.' + (oneHost ? ' Every request went to ' + DATA.http[0].host + '.' : '')), tools, t.el);
  root.onShow = () => t.refresh(); onState(() => { if (root.classList.contains('on')) t.refresh(); });
  return root;
}

function dnsView() {
  const d = DATA.dns;
  const resolved = vtable({ label: 'Names resolved by the proxy', empty: 'The proxy resolved no names', maxHeight: '360px', minWidth: '640px', rowHeight: 34,
    cols: [{ key: 'n', label: 'Name', w: 'minmax(160px,1.2fr)', cls: 'mono cell', render: x => x.name, sort: x => x.name }, { key: 'ip', label: 'Address(es)', w: 'minmax(140px,1fr)', cls: 'mono cell', render: x => x.ips.join(', ') }, { key: 'c', label: 'Lookups', w: '80px', cls: 'num', render: x => x.count, sort: x => x.count },
      { key: 'p', label: 'Ports', w: '110px', cls: 'mono cell', render: x => x.ports.join(', ') }, { key: 'pr', label: 'Processes', w: 'minmax(140px,1fr)', render: x => x.procs.slice(0, 3).map(pLabel).join(', ') + (x.procs.length > 3 ? ' +' + (x.procs.length - 3) : '') }, { key: 't', label: 'First', w: '80px', cls: 'num', render: x => fmtAt(x.first_t), sort: x => x.first_t }],
    rows: () => d.resolved.filter(x => qmatch(x.name, x.ips.join(' '))), defaultSort: 'c', defaultDir: -1 });
  const contacts = vtable({ label: 'Resolver contacts', empty: 'No process contacted a resolver', maxHeight: '300px', minWidth: '560px',
    cols: [{ key: 'p', label: 'Process', w: 'minmax(160px,1fr)', render: c => c.proc ? procLink(c.proc) : 'unattributed', sort: c => c.proc || '' }, { key: 'r', label: 'Resolver', w: 'minmax(160px,1fr)', cls: 'mono cell', render: c => c.resolver, sort: c => c.resolver }, { key: 'c', label: 'Times', w: '70px', cls: 'num', render: c => c.count, sort: c => c.count }, { key: 't', label: 'First', w: '80px', cls: 'num', render: c => fmtAt(c.first_t), sort: c => c.first_t }],
    rows: () => d.resolver_contacts.filter(c => qmatch(c.resolver, c.proc ? pLabel(c.proc) : '')), defaultSort: 't', defaultDir: 1, onSelect: c => c.proc && setState({ sel: { type: 'proc', id: c.proc } }) });
  const limits = h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'What this view can and cannot show')), h('div', { class: 'card-b' },
    h('div', { class: 'kv', style: { gridTemplateColumns: '170px 1fr' } },
      h('div', { class: 'k2' }, 'Names the proxy resolved'), h('div', { class: 'v2' }, h('span', { class: 'pill ok' }, 'exact'), ' For proxied traffic the proxy does the lookup, so the name asked for and the address returned are known exactly (top table).'),
      h('div', { class: 'k2' }, 'Lookups a process makes'), h('div', { class: 'v2' }, h('span', { class: 'pill warn' }, 'contact only'), ' When a program resolves a name itself (getaddrinfo, nscd, a DNS socket) only the contact with the resolver is visible. The query name is not: packet capture is unavailable here.'),
      h('div', { class: 'k2' }, 'Address-selection probes'), h('div', { class: 'v2' }, h('span', { class: 'pill' }, fmtN(d.lookup_probes)), ' UDP connect() calls that follow a lookup. libc uses them to sort the returned addresses; no packets are sent, so they are hidden from the network views.'),
      h('div', { class: 'k2' }, 'Encrypted DNS and QUIC'), h('div', { class: 'v2' }, 'DNS over HTTPS appears as ordinary HTTPS to the resolver. UDP payloads, including QUIC / HTTP/3, are never recorded.'))));
  const root = viewShell('dns', 'DNS & name resolution', 'Which names were looked up, what they resolved to, and which processes talked to a resolver.', h('div', { class: 'grid' }, limits,
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Resolved by the proxy'), h('span', { class: 'cnt' }, fmtN(d.resolved.length)), h('span', { class: 'sp' }), resolved.count), h('div', { class: 'card-b' }, resolved.el)),
    h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, 'Resolver contacts by processes'), h('span', { class: 'cnt' }, fmtN(d.resolver_contacts.length)), h('span', { class: 'sp' }), contacts.count), h('div', { class: 'card-b' }, contacts.el))));
  root.onShow = () => { resolved.refresh(); contacts.refresh(); }; onState(() => { if (root.classList.contains('on')) { resolved.refresh(); contacts.refresh(); } });
  return root;
}

function commandsView() {
  const f = { sev: '', failed: false };
  const t = vtable({ label: 'Commands', empty: 'No commands recorded', minWidth: '900px',
    cols: [{ key: 't', label: 'Started', w: '84px', cls: 'num', render: p => fmtAt(p.start), sort: p => p.start }, { key: 'pid', label: 'PID', w: '74px', cls: 'num', render: p => p.pid, sort: p => p.pid },
      { key: 'par', label: 'Parent', w: 'minmax(110px,.7fr)', render: p => p.parent ? procLink(p.parent) : h('span', { class: 'muted' }, p.detached ? 'detached' : 'root') },
      { key: 'sev', label: 'Flag', w: '96px', render: p => p.severity ? sevPill(p.severity) : '', sort: p => SEV[p.severity || 'info'].rank + (p.severity ? 1 : 0) },
      { key: 'ex', label: 'Exit', w: '110px', render: p => exitCell(p), sort: p => p.exit ? (p.exit.signal || p.exit.code || 0) : -1 },
      { key: 'cmd', label: 'Command', w: 'minmax(320px,3fr)', cls: 'mono cell', render: p => oneLine(p.cmdline) }],
    defaultSort: 't', defaultDir: 1,
    rows: () => DATA.processes.filter(p => inRange(p.start) && (!f.sev || p.severity === f.sev || (f.sev === 'any' && p.severity)) && (!f.failed || (p.exit && (p.exit.signal || p.exit.code))) && qmatch(p.cmdline, p.name, p.pid, p.cwd)),
    onSelect: p => setState({ sel: { type: 'proc', id: p.id } }), isSelected: p => S.sel && S.sel.type === 'proc' && S.sel.id === p.id });
  const tools = toolsRow(selectBox('Flag', [['', 'All commands'], ['any', 'Flagged only'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']], v => { f.sev = v; t.refresh(); }), h('button', { class: 'btn', type: 'button', 'aria-pressed': 'false', onclick: ev => { f.failed = !f.failed; ev.currentTarget.setAttribute('aria-pressed', String(f.failed)); t.refresh(); } }, 'Failed or killed only'), t.count);
  const root = h('div', { class: 'view col', id: 'view-commands' }, h('h2', { class: 'vt' }, 'Commands'), h('p', { class: 'vsub' }, 'Every program that was started, with its full command line (secrets redacted). This is the table form of the process tree.'), tools, t.el);
  root.onShow = () => t.refresh(); onState(() => { if (root.classList.contains('on')) t.refresh(); });
  return root;
}

function filesView() {
  const t = vtable({ label: 'File activity', empty: 'No activity on watched paths', minWidth: '720px',
    cols: [{ key: 't', label: 'At', w: '82px', cls: 'num', render: e => fmtAt(e.t), sort: e => e.t }, { key: 'p', label: 'Process', w: 'minmax(130px,.8fr)', render: e => e.proc ? procLink(e.proc) : '—' },
      { key: 'm', label: 'Access', w: '90px', render: e => h('span', { class: 'pill' + (e.detail.mode === 'read' ? '' : ' warn') }, e.detail.mode), sort: e => e.detail.mode },
      { key: 'c', label: 'Class', w: '110px', render: e => e.detail.category === 'credential' ? h('span', { class: 'sev sev-high' }, icon('x', 11), 'credential') : e.detail.category === 'staging' ? h('span', { class: 'sev sev-low' }, icon('warn', 11), 'temp dir') : e.detail.category, sort: e => e.detail.category },
      { key: 'path', label: 'Path', w: 'minmax(300px,3fr)', cls: 'mono cell', render: e => e.detail.path, sort: e => e.detail.path }],
    defaultSort: 't', defaultDir: 1, rows: () => DATA.events.filter(e => e.kind === 'file' && inRange(e.t) && qmatch(e.detail.path, e.proc ? pLabel(e.proc) : '', e.detail.mode)),
    onSelect: e => setState({ sel: { type: 'event', id: e.id } }), isSelected: e => S.sel && S.sel.type === 'event' && S.sel.id === e.id });
  const watch = DATA.run.file_watch || [];
  const root = h('div', { class: 'view col', id: 'view-files' }, h('h2', { class: 'vt' }, 'Files'),
    h('p', { class: 'vsub' }, 'File opens are recorded only for a watch list of credential stores and temporary directories, not every open: watching everything would drown the signal and slow the target.'),
    toolsRow(t.count), t.el, fileContents(), h('details', { class: 'card', style: { marginTop: '14px', padding: '10px 14px' } }, h('summary', { style: { cursor: 'pointer', color: 'var(--text-2)' } }, 'Watched path patterns (' + watch.length + ')'), h('pre', { class: 'code', style: { marginTop: '10px' } }, watch.join('\n') || '(not recorded)')));
  root.onShow = () => t.refresh(); onState(() => { if (root.classList.contains('on')) t.refresh(); });
  return root;
}

function fileContents() {   // what the target left in files it created or wrote: stored inert and redacted, shown as text only
  const fc = DATA.file_contents || [], cap = DATA.run.file_capture;
  const who = id => { const p = DATA.processes.find(q => q.id === id); return p ? p.name + ' (' + p.pid + ')' : 'unattributed'; };
  const item = f => {
    const notes = [];
    if (f.binary) notes.push('binary file: contents not stored');
    if (f.truncated) notes.push('only the first part was captured (' + fmtB(f.size) + ' in all)');
    if (f.redacted) notes.push('secrets were redacted');
    if (f.dropped_by_cap) notes.push('not stored: the size cap for captured contents was reached');
    const body = f.text !== undefined
      ? h('pre', { class: 'code fcode', tabindex: '0', 'aria-label': 'Contents of ' + f.path }, f.text)
      : h('p', { class: 'muted' }, f.binary ? 'First bytes (hex): ' + (f.head_hex || '') : 'No contents stored.');
    return h('details', { class: 'fc' },
      h('summary', null, h('span', { class: 'mono fpath' }, f.path), h('span', { class: 'muted' }, fmtB(f.size) + ' · written by ' + (f.writers.map(who).join(', ') || 'unattributed'))),
      notes.length ? h('p', { class: 'muted fnote' }, notes.join(' · ')) : null, body,
      f.sha256 ? h('p', { class: 'muted mono fnote' }, 'sha256 ' + f.sha256) : null);
  };
  const empty = !cap ? 'Contents were not captured for this recording.' : 'The target created or wrote no files on the watched paths.';
  return h('section', { class: 'card fcontents', 'aria-label': 'File contents' },
    h('h3', { class: 'fch' }, 'Contents of files the target created or wrote' + (fc.length ? ' (' + fc.length + ')' : '')),
    h('p', { class: 'muted fnote' }, 'Watched paths only, and only files the target opened for writing; files it merely read are never captured. Shown as inert text: control and direction-changing characters are escaped, and known secret shapes are redacted.'),
    fc.length ? fc.map(item) : h('p', { class: 'muted fnote' }, empty));
}

function eventsView() {
  const t = vtable({ label: 'Events', empty: 'No events match', minWidth: '720px', rowHeight: 30,
    cols: [{ key: 't', label: 'At', w: '86px', cls: 'num', render: e => fmtAt(e.t), sort: e => e.t }, { key: 'k', label: 'Kind', w: '110px', render: kindCell, sort: e => e.kind }, { key: 'p', label: 'Process', w: 'minmax(130px,.8fr)', render: e => e.proc ? procLink(e.proc) : h('span', { class: 'muted' }, '—') },
      { key: 'e', label: 'Event', w: 'minmax(320px,3fr)', cls: 'mono cell', render: e => oneLine(e.title) }],
    defaultSort: 't', defaultDir: 1,
    rows: () => DATA.events.filter(e => inRange(e.t) && S.kinds[groupOf(e)] && !(e.kind === 'udp' && e.detail.probe && !S.probes) && qmatch(e.title, e.kind, e.proc ? pLabel(e.proc) : '')),
    onSelect: e => setState({ sel: { type: 'event', id: e.id } }), isSelected: e => S.sel && S.sel.type === 'event' && S.sel.id === e.id });
  const legend = h('div', { class: 'legend' });
  const drawLegend = () => { clear(legend); for (const k of KINDS) legend.appendChild(h('button', { class: 'lg', type: 'button', 'aria-pressed': String(S.kinds[k.id]), onclick: () => setState({ kinds: { ...S.kinds, [k.id]: !S.kinds[k.id] } }) }, s('svg', { width: 11, height: 11, viewBox: '0 0 11 11', 'aria-hidden': 'true' }, marker(k.shape, 5.5, 5.5, 3.6, KC[k.id])), k.label)); if (S.range) legend.appendChild(h('button', { class: 'btn', type: 'button', onclick: () => setState({ range: null }) }, 'Clear time range')); };
  const root = h('div', { class: 'view col', id: 'view-events' }, h('h2', { class: 'vt' }, 'Events'), h('p', { class: 'vsub' }, 'The unified, time-ordered log of everything recorded: the table form of the timeline.'), toolsRow(legend, t.count), t.el);
  root.onShow = () => { drawLegend(); t.refresh(); }; onState(() => { if (root.classList.contains('on')) { drawLegend(); t.refresh(); } });
  return root;
}

function ruleReference() {   // the whole finding dictionary, with how many times each rule fired in THIS run
  const cat = DATA.catalog || {}, fired = {}; for (const f of DATA.findings) fired[f.rule] = (fired[f.rule] || 0) + 1;
  const ids = Object.keys(cat).sort((a, b) => (fired[b] ? 1 : 0) - (fired[a] ? 1 : 0) || cat[a].category.localeCompare(cat[b].category) || a.localeCompare(b));
  return h('details', { class: 'refrules' }, h('summary', null, 'Rule reference · ' + ids.length + ' rules, ' + Object.keys(fired).length + ' fired in this run'),
    h('p', { class: 'muted' }, 'What each rule means, what it cannot tell you, and how much real-world evidence stands behind it. Severities are heuristic estimates, not measurements.'),
    ...ids.map(id => { const c = cat[id]; return h('div', { class: 'refrule' }, h('div', { style: { display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, h('strong', null, c.title), h('span', { class: 'rule' }, id), h('span', { class: 'rstat ' + c.status }, (STATUS_TEXT[c.status] || [c.status])[0]), fired[id] ? h('span', { class: 'sev sev-medium' }, 'fired ×' + fired[id]) : null),
      h('p', { style: { margin: '4px 0', color: 'var(--text-2)' } }, c.meaning), h('p', { class: 'muted', style: { margin: '2px 0' } }, 'Cannot tell: ' + c.cannot_know), h('p', { class: 'muted', style: { margin: '2px 0' } }, 'Often benign: ' + c.benign.join('; ')), h('p', { class: 'muted', style: { margin: '2px 0 0' } }, 'Check: ' + c.check)); }));
}
function findingsView() {
  const f = { sev: new Set(['high', 'medium', 'low']) }, list = h('div', null);   // INFO starts collapsed: seven of nineteen is noise that pushes the real issues down
  const chips = h('div', { class: 'legend' });
  const draw = () => {
    clear(chips); for (const k of ['high', 'medium', 'low', 'info']) { const n = DATA.findings.filter(x => x.severity === k).length; chips.appendChild(h('button', { class: 'fchip', type: 'button', 'aria-pressed': String(f.sev.has(k)), title: (f.sev.has(k) ? 'Hide ' : 'Show ') + k + ' findings', onclick: () => { f.sev.has(k) ? f.sev.delete(k) : f.sev.add(k); draw(); } }, sevPill(k), h('span', { class: 'c num' }, String(n)), h('span', { class: 'fstate' }, f.sev.has(k) ? 'shown' : 'hidden'))); }
    clear(list); const shown = DATA.findings.filter(x => f.sev.has(x.severity) && qmatch(x.title, x.why, x.rule, x.category, x.detail));
    if (!shown.length) list.appendChild(h('div', { class: 'empty' }, DATA.findings.length ? 'No findings match the filters.' : 'No indicators fired for this run.'));
    for (const x of shown) list.appendChild(h('div', { style: { cursor: 'pointer' }, onclick: ev => { if (!ev.target.closest('button,.ev-item,details')) setState({ sel: { type: 'finding', id: x.id } }); } }, findingCard(x)));
  };
  const root = viewShell('findings', 'Findings', 'Indicators derived from what was recorded. Each one cites its evidence. They are for a human to judge: a rule firing means "look here", not "this is malicious".', chips, h('div', { style: { height: '10px' } }), list, ruleReference());
  root.onShow = draw; onState(() => { if (root.classList.contains('on')) draw(); });
  return root;
}

function runView() {
  const r = DATA.run, ig = DATA.integrity, red = DATA.redactions || {}, clk = DATA.clock;
  const redTotals = {}; for (const src of ['recorder', 'proxy']) for (const [k, v] of Object.entries(red[src] || {})) redTotals[k] = (redTotals[k] || 0) + v;
  const dl = () => { const blob = new Blob([document.getElementById('tw-data').textContent], { type: 'application/json' }); const a = h('a', { href: URL.createObjectURL(blob), download: 'tracewatch-' + r.id + '.json' }); document.body.appendChild(a); a.click(); a.remove(); };
  const card = (title, ...kids) => h('section', { class: 'card' }, h('div', { class: 'card-h' }, h('h3', null, title)), h('div', { class: 'card-b' }, ...kids));
  const root = viewShell('run', 'Run & integrity', 'How this run was recorded, what can be trusted, and what the recorder could not see.',
    h('div', { class: 'grid g2' },
      card('Integrity', kv([['Verdict', h('span', { class: 'verdict ' + verdictClass() }, icon(verdictOf()[1], 14), r.verdict)], ['Reasons', r.reasons.length ? h('div', null, r.reasons.map(x => h('div', null, x))) : 'none'], ['Gaps', (ig.gaps || []).length ? h('div', null, ig.gaps.map(g => h('div', null, g.source + ': ' + g.reason))) : 'none'], ['Size caps hit', (r.caps_hit || []).join(', ') || 'none'], ['Lost components', (r.lost_components || []).join(', ') || 'none'],
        ['Unproxied', (ig.unproxied || []).length ? h('div', null, ig.unproxied.map(u => h('div', { class: 'mono' }, `${u.dst}:${u.port} ×${u.count}`))) : 'none']]), h('div', { style: { marginTop: '12px' } }, coverageStrip())),
      card('Recorder', kv([['Run id', r.id], ['Started', fmtWall(r.started_wall_ns) + ' (wall clock, approximate)'], ['Duration', fmtT(r.duration_ns)], ['Command', h('span', { class: 'mono' }, r.cmdline)], ['Working dir', r.cwd], ['Policy', r.policy ? `recorder death → ${r.policy.on_recorder_death}; component loss → ${r.policy.on_component_loss}` : null],
        ['Tracee', r.versions && r.versions.tracee ? (r.versions.tracee.version || '') + ' · ' + short((r.versions.tracee.digest || '').split('@').pop(), 20) : null], ['mitmproxy', r.versions ? r.versions.mitmproxy : null], ['tracewatch', DATA.generator.tracewatch], ['Clock alignment', `${clk.source}${clk.votes ? ' · ' + clk.votes + ' anchor(s)' : ''}`],
        ['Size limits', r.limits ? `flows ${fmtB(r.limits.max_flows_bytes)} (bodies off at ${fmtB(r.limits.soft_flows_bytes)}) · tracee ${fmtB(r.limits.max_tracee_bytes)}` : null]])),
      card('Redactions', Object.keys(redTotals).length ? h('div', { class: 'legend' }, Object.entries(redTotals).sort((a, b) => b[1] - a[1]).map(([k, v]) => h('span', { class: 'pill' }, k + ' ×' + v))) : h('div', { class: 'muted' }, 'No secrets were redacted.'), h('p', { class: 'muted', style: { marginBottom: 0 } }, 'Secrets are replaced by keyed tags before anything is written. Redaction is heuristic: a secret with an unusual shape under an innocuous name is not caught, so treat the run directory as sensitive.')),
      card('Notes and limits', h('ul', { style: { margin: 0, paddingLeft: '18px', color: 'var(--text-2)' } }, DATA.notes.map(n => h('li', { style: { marginBottom: '5px' } }, n))))),
    h('div', { style: { marginTop: '14px', display: 'flex', gap: '8px' } }, h('button', { class: 'btn', type: 'button', onclick: dl }, 'Download report data (JSON)')));
  return root;
}

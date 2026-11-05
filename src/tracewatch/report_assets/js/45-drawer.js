/* ===== detail drawer: process / event / http / finding / destination ===== */
const drawerEl = h('aside', { id: 'drawer', 'aria-label': 'Details', role: 'dialog', 'aria-modal': 'false', tabindex: '-1' });
let drawerOpener = null, drawerOpenerKey = null, drawerWasOpen = false;
const closeDrawer = () => setState({ sel: null });
function kv(rows) {
  const g = h('div', { class: 'kv' });
  for (const [k, v] of rows) { if (v === undefined || v === null || v === '') continue; g.appendChild(h('div', { class: 'k2' }, k)); g.appendChild(h('div', { class: 'v2' }, v instanceof Node ? v : String(v))); }
  return g;
}
const section = (title, ...kids) => h('div', { class: 'sec' }, h('h4', null, title), ...kids);
function codeBlock(text, opts) { opts = opts || {}; return h('pre', { class: 'code', style: opts.maxHeight ? { maxHeight: opts.maxHeight } : null }, text, opts.copy === false ? null : copyBtn(text)); }
function chainNodes(pid) {
  const c = h('div', { class: 'chain' }); const ch = chainOf(pid);
  ch.forEach((p, i) => { if (i) c.appendChild(h('span', { class: 'arr' }, '→')); c.appendChild(h('button', { type: 'button', class: 'cn' + (p.id === pid ? ' cur' : ''), title: short(oneLine(p.cmdline), 200), onclick: () => setState({ sel: { type: 'proc', id: p.id } }) }, p.name + ' ', h('span', { class: 'muted mono' }, String(p.pid)))); });
  return c;
}
function evItem(e) {
  const kk = KINDS.find(z => z.id === groupOf(e));
  return h('div', { class: 'ev-item', tabindex: '0', onclick: () => setState({ sel: { type: e.kind === 'http' ? 'http' : 'event', id: e.kind === 'http' ? e.detail.flow_id : e.id } }), onkeydown: ev => { if (ev.key === 'Enter') ev.target.click(); } },
    h('span', { class: 'tt2' }, fmtAt(e.t)), s('svg', { width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true' }, marker(kk.shape, 6, 6, 3.8, KC[kk.id])), h('span', { class: 'mono', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, short(oneLine(e.title), 120)));
}
function findingCard(f, compact) {
  return h('div', { class: 'finding', style: { borderLeft: '3px solid ' + SEVC[f.severity] } },
    h('div', { style: { display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' } }, sevPill(f.severity), h('span', { class: 'rule' }, f.rule), h('span', { class: 'muted', style: { marginLeft: 'auto' } }, f.category)),
    h('h4', null, f.title), compact ? null : h('p', null, f.why), f.detail ? h('p', { class: 'muted mono', style: { fontSize: '11.5px' } }, short(f.detail, 400)) : null,
    f.events.length ? h('div', { class: 'ev-list' }, f.events.slice(0, 6).map(id => E.get(id)).filter(Boolean).map(evItem)) : null,
    f.procs.length ? h('div', { class: 'chain', style: { marginTop: '8px' } }, f.procs.slice(0, 8).map(id => h('button', { type: 'button', class: 'cn', onclick: () => setState({ sel: { type: 'proc', id } }) }, pLabel(id)))) : null);
}
function headerTable(rows) {
  if (!rows || !rows.length) return h('div', { class: 'muted' }, 'none');
  return h('table', { class: 'plain' }, h('tbody', null, rows.map(([k, v]) => h('tr', null, h('td', { class: 'mono', style: { color: 'var(--text-3)', whiteSpace: 'nowrap', verticalAlign: 'top' } }, k), h('td', { class: 'mono', style: { wordBreak: 'break-all' } }, v)))));
}
function bodyBlock(b) {
  if (!b || (b.captured === undefined && !b.size)) return h('div', { class: 'muted' }, 'no body');
  if (!b.captured) return h('div', { class: 'muted' }, `${fmtB(b.size)} ${b.content_type || ''} · not stored: ${b.reason || 'unknown'}`);
  return h('div', null, h('div', { class: 'muted', style: { marginBottom: '5px' } }, `${fmtB(b.size)} ${b.content_type || ''}${b.truncated ? ' · truncated after redaction' : ''}`), codeBlock(b.text, { maxHeight: '300px' }));
}
function tlsBlock(t) {
  if (!t) return null;
  const c = t.cert || {};
  return section('TLS (proxy → server)', kv([['Version', t.version], ['Cipher', t.cipher], ['ALPN', t.alpn], ['SNI', t.sni], ['Subject', c.subject_cn], ['Issuer', [c.issuer_cn, c.issuer_o].filter(Boolean).join(' · ')], ['Valid until', c.not_after ? c.not_after.slice(0, 10) : null]]));
}

function procDrawer(p) {
  const evs = (evByProc.get(p.id) || []).filter(e => !(e.kind === 'udp' && e.detail.probe));
  const fs = DATA.findings.filter(f => f.procs.includes(p.id));
  return [
    h('div', { class: 'dh' }, h('div', { class: 't' }, h('div', { class: 'k' }, 'Process'), h('h3', null, p.name + '  ', h('span', { class: 'muted mono', style: { fontWeight: 400 } }, String(p.pid)))), p.severity ? sevPill(p.severity) : null, closeBtn()),
    h('div', { class: 'db' },
      section('Command line', codeBlock(p.cmdline)),
      section('Process chain', chainNodes(p.id)),
      section('Details', kv([['PID / PPID', `${p.pid} / ${p.ppid}`], ['User (uid)', p.uid], ['Working dir', p.cwd], ['Executable', p.exe], ['Started', fmtAt(p.start)], ['Ended', p.end === null ? 'not recorded' : fmtAt(p.end)], ['Lifetime', p.end === null ? '—' : fmtT(p.end - p.start)],
        ['Exit', exitCell(p)], ['Origin', p.forked ? 'fork of its parent (never exec\'d): shown with the parent\'s command line' : p.detached ? 'detached: its parent was not recorded' : 'exec'], ['Children', String(p.children.length)]])),
      p.execs.length > 1 ? section('Exec history', h('div', { class: 'ev-list' }, p.execs.map(x => h('div', { class: 'ev-item', style: { gridTemplateColumns: '64px 1fr' } }, h('span', { class: 'tt2' }, fmtAt(x.t)), h('span', { class: 'mono' }, short(oneLine(cmdline(x.argv)), 160)))))) : null,
      fs.length ? section('Findings (' + fs.length + ')', fs.map(f => findingCard(f, true))) : null,
      p.children.length ? section('Children (' + p.children.length + ')', h('div', { class: 'chain' }, p.children.slice(0, 40).map(id => h('button', { type: 'button', class: 'cn', onclick: () => setState({ sel: { type: 'proc', id } }) }, pLabel(id))), p.children.length > 40 ? h('span', { class: 'muted' }, '… +' + (p.children.length - 40)) : null)) : null,
      section('Activity (' + evs.length + ')', evs.length ? h('div', { class: 'ev-list' }, evs.slice(0, 200).map(evItem), evs.length > 200 ? h('div', { class: 'muted', style: { padding: '6px' } }, `… ${evs.length - 200} more in the Events tab`) : null) : h('div', { class: 'muted' }, 'No events recorded for this process.'))),
  ];
}
function cmdline(argv) { return argv.map(a => /^[A-Za-z0-9_\/.:=@%+,-]+$/.test(a) ? a : "'" + String(a).replace(/'/g, "'\"'\"'") + "'").join(' '); }
function closeBtn() { return h('button', { class: 'iconbtn', type: 'button', 'aria-label': 'Close details', title: 'Close (Esc)', onclick: closeDrawer }, icon('close', 16)); }

function eventDrawer(e) {
  const d = e.detail || {}; const rows = [['Time', fmtAt(e.t)], ['Process', e.proc ? procLink(e.proc) : 'unattributed'], ['Kind', e.kind + (e.sub ? ' · ' + e.sub : '')]];
  for (const [k, v] of Object.entries(d)) { if (['argv'].includes(k)) continue; rows.push([k, typeof v === 'object' ? JSON.stringify(v) : String(v)]); }
  const rel = DATA.findings.filter(f => f.events.includes(e.id));
  return [
    h('div', { class: 'dh' }, h('div', { class: 't' }, h('div', { class: 'k' }, 'Event · ' + (KINDS.find(z => z.id === groupOf(e)) || {}).label), h('h3', { class: 'mono', style: { fontSize: '13px' } }, short(oneLine(e.title), 300))), closeBtn()),
    h('div', { class: 'db' }, e.proc ? section('Process chain', chainNodes(e.proc)) : null, section('Details', kv(rows)), d.argv ? section('Command line', codeBlock(cmdline(d.argv))) : null,
      rel.length ? section('Findings', rel.map(f => findingCard(f, true))) : null),
  ];
}
function statusPill(x) {
  if (x.error) return h('span', { class: 'sev sev-medium' }, icon('warn', 12), 'error');
  const c = x.status; if (c === null || c === undefined) return h('span', { class: 'muted' }, '—');
  if (c >= 500) return h('span', { class: 'sev sev-high' }, icon('x', 12), String(c));
  if (c >= 400) return h('span', { class: 'sev sev-medium' }, icon('warn', 12), String(c));
  return h('span', { class: 'pill ' + (c >= 300 ? '' : 'ok') }, String(c));
}
function httpDrawer(x) {
  const w = DATA.websockets.find(z => z.flow_id === x.id), rel = DATA.findings.filter(f => f.events.includes(x.event));
  const total = x.duration_ms || 0, ttfb = x.ttfb_ms || 0;
  return [
    h('div', { class: 'dh' }, h('div', { class: 't' }, h('div', { class: 'k' }, (w ? 'WebSocket' : 'HTTP') + ' · ' + (x.http_version || x.scheme)), h('h3', { class: 'mono', style: { fontSize: '13px' } }, x.method + ' ' + x.scheme + '://' + x.host + x.path)), statusPill(x), closeBtn()),
    h('div', { class: 'db' },
      x.proc ? section('Process chain', chainNodes(x.proc)) : section('Process', h('div', { class: 'muted' }, 'Not attributed: ' + (x.attribution.candidates.length ? 'ambiguous between pids ' + x.attribution.candidates.join(', ') : 'the client had exited before the proxy could look it up'))),
      section('Summary', kv([['Status', x.error ? 'error: ' + x.error : x.status], ['At', fmtAt(x.t)], ['Duration', x.duration_ms !== null && x.duration_ms !== undefined ? x.duration_ms + ' ms' : null], ['Time to first byte', x.ttfb_ms !== null && x.ttfb_ms !== undefined ? x.ttfb_ms + ' ms' : null], ['Server address', x.server_ip ? x.server_ip + ':' + x.port : null], ['Process', x.proc ? procLink(x.proc) : null], ['Connection opened by', x.attribution.opener_proc && x.attribution.opener_proc !== x.proc ? procLink(x.attribution.opener_proc) : null], ['Attributed by', x.attribution.method]]), x.attribution.method === 'shared-socket-sender-unknown' ? h('div', { class: 'muted', style: { marginTop: '6px' } }, 'Several processes (pids ' + x.attribution.candidates.join(', ') + ') held this connection and nothing recorded shows which of them sent the request; the process shown opened it.') : null),
      total ? section('Timing', h('div', { class: 'timing', role: 'img', 'aria-label': `${ttfb} ms to first byte of ${total} ms total` }, h('i', { style: { width: (100 * ttfb / total) + '%', background: 'var(--k-http)' } }), h('i', { style: { width: Math.max(1, 100 - 100 * ttfb / total) + '%', background: 'rgba(217,89,38,.4)' } })), h('div', { class: 'muted', style: { marginTop: '4px' } }, `waiting ${ttfb} ms · transfer ${Math.max(0, total - ttfb)} ms`)) : null,
      tlsBlock(x.tls), rel.length ? section('Findings', rel.map(f => findingCard(f, true))) : null,
      section('Request headers', headerTable(x.req_headers)), section('Request body', bodyBlock(x.req_body)),
      section('Response headers', headerTable(x.resp_headers)), section('Response body', bodyBlock(x.resp_body)),
      w ? section(`WebSocket messages (${(w.log || []).length} recorded${w.suppressed ? ', ' + w.suppressed + ' suppressed' : ''})`, kv([['Close', (w.close_code ?? '—') + (w.close_reason ? ' · ' + w.close_reason : '')], ['Clean', w.clean === null ? '—' : w.clean ? 'yes' : 'no: no close frame was exchanged'], ['Messages', `${(w.messages || {}).c2s || 0} sent · ${(w.messages || {}).s2c || 0} received`]]),
        h('div', { class: 'ev-list', style: { marginTop: '8px', maxHeight: '320px', overflow: 'auto' } }, (w.log || []).slice(0, 300).map(m => h('div', { class: 'ev-item', style: { gridTemplateColumns: '38px 14px 1fr', cursor: 'default' } }, h('span', { class: 'tt2' }, m.dir === 'c2s' ? '→ out' : '← in'), h('span', { class: 'muted' }, m.opcode === 'binary' ? 'B' : 'T'), h('span', { class: 'mono', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, m.body.captured ? short(oneLine(m.body.text), 160) : `(${fmtB(m.body.size)} · ${m.body.reason})`))))) : null),
  ];
}
function findingDrawer(f) {
  return [h('div', { class: 'dh' }, h('div', { class: 't' }, h('div', { class: 'k' }, 'Finding · ' + f.category), h('h3', null, f.title)), sevPill(f.severity), closeBtn()),
    h('div', { class: 'db' }, section('What this means', h('p', { style: { margin: 0, color: 'var(--text-2)' } }, f.why), f.detail ? h('p', { class: 'mono muted', style: { fontSize: '11.5px' } }, f.detail) : null),
      section('Rule', h('span', { class: 'mono' }, f.rule), h('p', { class: 'muted', style: { marginBottom: 0 } }, 'Indicators are for a human to judge. A rule firing means "look here"; it cannot know your intent.')),
      f.events.length ? section('Evidence (' + f.events.length + ')', h('div', { class: 'ev-list' }, f.events.map(id => E.get(id)).filter(Boolean).slice(0, 80).map(evItem))) : null,
      f.procs.length ? section('Processes', f.procs.map(id => h('div', { style: { marginBottom: '8px' } }, chainNodes(id)))) : null)];
}
function destDrawer(d) {
  const reqs = d.via === 'proxy' ? DATA.http.filter(x => x.host === d.name && x.port === d.port) : DATA.events.filter(e => e.kind === 'tcp' && e.detail.dst === d.ip && e.detail.port === d.port);
  return [h('div', { class: 'dh' }, h('div', { class: 't' }, h('div', { class: 'k' }, d.via === 'proxy' ? 'Destination · recorded via proxy' : 'Destination · DIRECT (content not recorded)'), h('h3', { class: 'mono', style: { fontSize: '14px' } }, (d.name || d.ip) + ':' + d.port)), closeBtn()),
    h('div', { class: 'db' }, d.via === 'direct' ? h('div', { class: 'finding', style: { borderLeft: '3px solid ' + SEVC.medium, marginTop: '12px' } }, h('p', null, 'These connections did not pass through the recorder\'s proxy, so only the kernel saw them: destination and process, no content.')) : null,
      section('Summary', kv([['Address', d.ip], ['Name', d.name], ['Port', d.port], [d.via === 'proxy' ? 'Requests' : 'Connections', fmtN(d.requests)], ['Errors', d.via === 'proxy' ? fmtN(d.errors) : null], ['Bytes in / out', d.via === 'proxy' ? fmtB(d.bytes_in) + ' / ' + fmtB(d.bytes_out) : null], ['First seen', fmtAt(d.first_t)], ['Processes', h('span', { class: 'chain' }, d.procs.slice(0, 12).map(id => h('button', { type: 'button', class: 'cn', onclick: () => setState({ sel: { type: 'proc', id } }) }, pLabel(id))))]])),
      tlsBlock(d.tls),
      section((d.via === 'proxy' ? 'Requests' : 'Connections') + ' (' + reqs.length + ')', h('div', { class: 'ev-list' }, (d.via === 'proxy' ? reqs.slice(0, 120).map(x => E.get(x.event)).filter(Boolean) : reqs.slice(0, 120)).map(evItem))))];
}
function syncDrawer() {
  const sel = S.sel; let content = null;
  if (sel) {
    if (sel.type === 'proc' && P.has(sel.id)) content = procDrawer(P.get(sel.id));
    else if (sel.type === 'event' && E.has(sel.id)) { const e = E.get(sel.id); content = e.kind === 'http' && HX.has(e.detail.flow_id) ? httpDrawer(HX.get(e.detail.flow_id)) : eventDrawer(e); }
    else if (sel.type === 'http' && HX.has(sel.id)) content = httpDrawer(HX.get(sel.id));
    else if (sel.type === 'finding' && FD.has(sel.id)) content = findingDrawer(FD.get(sel.id));
    else if (sel.type === 'dest') content = destDrawer(DATA.destinations[sel.id]);
  }
  clear(drawerEl);
  if (content) {
    if (!drawerWasOpen) { drawerOpener = document.activeElement; drawerOpenerKey = (drawerOpener && drawerOpener.getAttribute && (drawerOpener.getAttribute('data-fk') || drawerOpener.dataset.fk)) || null; }   // remember who opened it so Esc can hand focus back
    add(drawerEl, content); drawerEl.classList.add('open'); drawerEl.removeAttribute('aria-hidden'); drawerEl.removeAttribute('inert');
    // defer: moving focus inside the SAME keystroke would hand that Enter's click to the close button and shut the drawer
    const first = $('.dh .iconbtn', drawerEl); if (!drawerWasOpen && first) setTimeout(() => first.focus({ preventScroll: true }), 30);
    drawerWasOpen = true;
  } else {
    drawerEl.classList.remove('open'); drawerEl.setAttribute('aria-hidden', 'true'); drawerEl.setAttribute('inert', '');   // hidden content must not be tabbable
    if (drawerWasOpen) {   // the opener may have been re-rendered (new element, same key): find it again
      const back = (drawerOpener && document.contains(drawerOpener)) ? drawerOpener : (drawerOpenerKey ? document.querySelector('[data-fk="' + drawerOpenerKey.replace(/"/g, '\\"') + '"]') : null);
      if (back && back.focus) back.focus({ preventScroll: true });
    }
    drawerWasOpen = false; drawerOpener = null; drawerOpenerKey = null;
  }
}

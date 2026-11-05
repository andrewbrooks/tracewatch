/* ===== "How it unfolded": the notable steps as a one-line ribbon above the activity lanes ===== */
const STAGE = {   // finding category -> plain-language stage
  execution: 'Execution', credential: 'Credential access', exposure: 'Data exposure', network: 'Network',
  evasion: 'Evasion', privilege: 'Privilege', integrity: 'Recording', reliability: 'Reliability',
};
const STORY_SKIP = new Set(['recording-integrity', 'secrets-redacted', 'nonzero-exit', 'inline-code', 'killed-by-signal', 'detached-process']);
const STORY_MAX = 12, STORY_GROUP_NS = 1.5e9;
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3 };
function storySteps() {
  const base = DATA.findings.filter(f => (f.severity === 'high' || f.severity === 'medium') && !STORY_SKIP.has(f.rule) && f.events.length).sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));
  const steps = [];
  for (const f of base) {   // consecutive findings of the same rule in quick succession read as one step ("x3"), not three
    const last = steps[steps.length - 1];
    if (last && last.rule === f.rule && f.t - last.tEnd <= STORY_GROUP_NS) { last.items.push(f); last.tEnd = f.t; if (SEV_RANK[f.severity] > SEV_RANK[last.severity]) last.severity = f.severity; }
    else steps.push({ rule: f.rule, category: f.category, severity: f.severity, t: f.t, tEnd: f.t, items: [f] });
  }
  return steps;
}
function storyRibbon() {
  const all = storySteps(); if (all.length < 2) return null;
  const steps = all.slice(0, STORY_MAX), more = all.length - steps.length;
  const track = h('ol', { class: 'ribbon', 'aria-label': 'Notable steps in time order' });
  steps.forEach((st, i) => {
    const f = st.items[0], stage = STAGE[st.category] || st.category;
    if (i) track.appendChild(h('li', { class: 'ribbon-gap', 'aria-hidden': 'true' }, '›'));
    track.appendChild(h('li', null, h('button', { type: 'button', class: 'rchip st-' + st.severity, 'data-fk': 'story:' + i,
      title: stage + ': ' + f.title + (st.items.length > 1 ? ` (and ${st.items.length - 1} more of the same kind)` : '') + ' · ' + fmtAt(st.t) + (i ? ' · ' + fmtT(Math.max(0, st.t - steps[i - 1].tEnd)) + ' after the previous step' : ''),
      onclick: () => setState({ sel: { type: 'finding', id: f.id } }) },
      icon(SEVICON[st.severity], 12), h('span', { class: 'rtitle' }, short(f.title, 44)), st.items.length > 1 ? h('span', { class: 'rn' }, '×' + st.items.length) : null, h('span', { class: 'rtime' }, fmtAt(st.t)))));
  });
  if (more) track.appendChild(h('li', null, h('button', { type: 'button', class: 'rchip more', onclick: () => setState({ tab: 'findings' }) }, '+' + more + ' more in Findings')));
  const fade = () => track.classList.toggle('more-right', track.scrollWidth - track.clientWidth - track.scrollLeft > 4);
  track.addEventListener('scroll', fade); new ResizeObserver(fade).observe(track); requestAnimationFrame(fade);
  return h('div', { class: 'ribbon-wrap' }, h('span', { class: 'ribbon-label' }, 'How it unfolded'), track);
}

/* ===== the sequence of notable events: how the run unfolded, in order, as a connected chain ===== */
const STAGE = {   // finding category -> plain-language stage + the icon that stands for it
  execution: ['Execution', 'commands'], credential: ['Credential access', 'files'], exposure: ['Data exposure', 'http'], network: ['Network', 'network'],
  evasion: ['Evasion', 'search'], privilege: ['Privilege', 'findings'], integrity: ['Recording', 'run'], reliability: ['Reliability', 'info'],
};
const STORY_SKIP = new Set(['recording-integrity', 'secrets-redacted', 'nonzero-exit', 'inline-code', 'killed-by-signal', 'detached-process']);
const STORY_MAX = 10, STORY_GROUP_NS = 1.5e9;
function storySteps() {
  const base = DATA.findings.filter(f => (f.severity === 'high' || f.severity === 'medium') && !STORY_SKIP.has(f.rule) && f.events.length).sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));
  const steps = [];
  for (const f of base) {   // consecutive findings of the same rule in quick succession read as one step ("×3"), not three
    const last = steps[steps.length - 1];
    if (last && last.rule === f.rule && f.t - last.tEnd <= STORY_GROUP_NS) { last.items.push(f); last.tEnd = f.t; if (SEV_RANK[f.severity] > SEV_RANK[last.severity]) last.severity = f.severity; }
    else steps.push({ rule: f.rule, category: f.category, severity: f.severity, t: f.t, tEnd: f.t, items: [f] });
  }
  return steps;
}
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3 };
function storyChain() {
  const all = storySteps(); if (all.length < 2) return null;
  const steps = all.slice(0, STORY_MAX), more = all.length - steps.length;
  const track = h('ol', { class: 'story-track', 'aria-label': 'Notable events in time order' });
  steps.forEach((s, i) => {
    const [stage, ic] = STAGE[s.category] || [s.category, 'info'], f = s.items[0], p = f.procs.length ? P.get(f.procs[0]) : null;
    if (i) track.appendChild(h('li', { class: 'story-link', 'aria-hidden': 'true' }, h('span', { class: 'story-gap' }, '+' + fmtT(Math.max(0, s.t - steps[i - 1].tEnd)))));
    track.appendChild(h('li', { class: 'story-item' }, h('button', { type: 'button', class: 'story-node st-' + s.severity, 'data-fk': 'story:' + i,
      title: f.title + (s.items.length > 1 ? ` (and ${s.items.length - 1} more of the same kind)` : ''), onclick: () => setState({ sel: { type: 'finding', id: f.id } }) },
      h('span', { class: 'story-stage' }, icon(ic, 14), stage, s.items.length > 1 ? h('span', { class: 'story-n' }, '×' + s.items.length) : null),
      h('span', { class: 'story-title' }, short(f.title, 64)),
      h('span', { class: 'story-meta' }, fmtAt(s.t), p ? ' · ' + p.name : ''))));
  });
  const fade = () => track.classList.toggle('more-right', track.scrollWidth - track.clientWidth - track.scrollLeft > 4);   // a hint that the row scrolls
  track.addEventListener('scroll', fade); new ResizeObserver(fade).observe(track); requestAnimationFrame(fade);
  return h('section', { class: 'card story' }, h('div', { class: 'card-h' }, h('h3', null, 'How it unfolded'), h('span', { class: 'cnt' }, fmtN(all.length) + (all.length === 1 ? ' step' : ' steps')), h('span', { class: 'sp' }),
    more ? h('button', { class: 'btn', type: 'button', onclick: () => setState({ tab: 'findings' }) }, '+' + more + ' more in Findings') : null),
    h('div', { class: 'card-b' }, h('p', { class: 'muted', style: { margin: '0 0 10px' } }, 'High and medium findings in time order; gaps are the time between steps. Click one for details. These are indicators, not a verdict.'), track));
}

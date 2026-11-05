"""`tracewatch diff --format html`: a static, script-free page. Every recorded string is HTML-escaped on the server
side and the CSP allows no script at all, so a hostile command line or URL has nothing to run in. Colours come from
the interactive report's own tokens (dark by default, light when the OS asks for it)."""

from __future__ import annotations

import html
import re
import secrets

from .report_html import read_assets

NAMES = {
    "commands": "Commands",
    "destinations": "Destinations",
    "http": "HTTP requests",
    "dns": "DNS names",
    "files": "File activity",
    "findings": "Findings",
}
VERDICT_LABEL = {
    "complete": "Complete",
    "complete-with-losses": "Complete with losses",
    "incomplete": "Incomplete",
    "in-progress": "In progress",
}

PAGE_CSS = """
body { margin: 0; background: var(--page); color: var(--text); font: 14px/1.5 var(--font); }
main { max-width: 1100px; margin: 0 auto; padding: 28px 20px 60px; }
h1 { font-size: 20px; margin: 0 0 4px; } h2 { font-size: 15px; margin: 0; }
.mono { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.muted { color: var(--text-3); }
.runs { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 16px 0; }
.card { background: var(--raised); border: 1px solid var(--line); border-radius: var(--radius); padding: 12px 14px; }
.card .k { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--text-3); }
.banner { border: 1px solid var(--line-2); border-radius: var(--radius); padding: 14px 16px; margin: 0 0 16px;
  background: var(--raised); display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.banner b { font-size: 16px; }
.pill { display: inline-block; border: 1px solid var(--line-2); border-radius: 99px; padding: 1px 9px; font-size: 12px; }
ul.notable { margin: 8px 0 0; padding-left: 18px; } ul.notable li { margin: 3px 0; overflow-wrap: anywhere; }
details { background: var(--raised); border: 1px solid var(--line); border-radius: var(--radius); margin: 12px 0; }
summary { cursor: pointer; padding: 10px 14px; display: flex; gap: 10px; align-items: baseline; }
summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 6px 14px; border-top: 1px solid var(--line); vertical-align: top; }
th { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--text-3); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.tag { display: inline-block; min-width: 76px; font-weight: 700; font-size: 11.5px; letter-spacing: .04em; }
.t-added { color: var(--t-good); } .t-removed { color: var(--t-critical); } .t-changed { color: var(--t-warning); }
.wrap { overflow-x: auto; }
@media (max-width: 700px) { .runs { grid-template-columns: 1fr; } main { padding: 18px 12px 40px; } }
@media print { details { break-inside: avoid; } body { background: #fff; color: #000; } }
"""


def _tokens() -> str:
    """The dark token block as :root, the light block re-scoped to the OS preference (there is no toggle here)."""
    css, _ = read_assets()
    dark = css[css.index(":root {") : css.index("}", css.index(":root {")) + 1]
    lstart = css.index(':root[data-theme="light"] {')
    light = css[lstart : css.index("}", lstart) + 1].replace(':root[data-theme="light"]', ":root", 1)
    return dark + "\n@media (prefers-color-scheme: light) {\n" + light + "\n}\n"


def esc(s) -> str:
    t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(s if s is not None else ""))
    return html.escape(t, quote=True)


def _short(v) -> str:
    return esc(v if not isinstance(v, (list, dict)) else str(v))


def _rows(section: dict) -> str:
    out = []
    for tag, label, sign in (("added", "ADDED", "+"), ("removed", "REMOVED", "−")):
        for it in section[tag]:
            extra = ", ".join(f"{k}={_short(v)}" for k, v in it.items() if k != "key" and v not in (None, "", [], {}))
            out.append(
                f'<tr><td><span class="tag t-{tag}"><span aria-hidden="true">{sign}</span> {label}</span></td>'
                f'<td class="mono">{esc(it["key"])}</td><td class="muted">{esc(extra)}</td></tr>'
            )
    for it in section.get("changed", []):
        delta = "; ".join(f"{k}: {_short(v[0])} → {_short(v[1])}" for k, v in it["delta"].items())
        out.append(
            '<tr><td><span class="tag t-changed"><span aria-hidden="true">~</span> CHANGED</span></td>'
            f'<td class="mono">{esc(it["key"])}</td><td>{esc(delta)}</td></tr>'
        )
    return "".join(out)


def render(d: dict) -> str:
    from . import __version__

    nonce = secrets.token_urlsafe(18)
    b, a = d["before"], d["after"]
    n_changes = sum(len(s["added"]) + len(s["removed"]) + len(s.get("changed", [])) for s in d["sections"].values())

    def run_card(label: str, r: dict) -> str:
        return (
            f'<div class="card"><div class="k">{label}</div><div class="mono">{esc(r["cmdline"])}</div>'
            f'<div class="muted">run {esc(r["id"])} · {esc(VERDICT_LABEL.get(r["verdict"], r["verdict"]))} · '
            f"{r['duration_ns'] / 1e9:.1f}s</div></div>"
        )

    if d["changed"]:
        banner = (
            f'<div class="banner"><b><span aria-hidden="true">Δ</span> Behaviour changed</b>'
            f'<span class="muted">{n_changes} difference{"s" if n_changes != 1 else ""}</span></div>'
        )
    else:
        banner = (
            '<div class="banner"><b><span aria-hidden="true">✓</span> No behavioural change</b>'
            '<span class="muted">same commands, destinations, requests, files and findings</span></div>'
        )
    notable = ""
    if d["notable"]:
        shown = d["notable"][:15]
        items = "".join(f"<li>{esc(n)}</li>" for n in shown)
        more = f"<li>…and {len(d['notable']) - 15} more (see the sections below)</li>" if len(d["notable"]) > 15 else ""
        notable = (
            f'<section aria-label="What changed"><h2>What changed</h2><ul class="notable">{items}{more}</ul></section>'
        )
    totals = "".join(
        f'<tr><td>{esc(k)}</td><td class="num">{b["stats"][k]}</td><td class="num">{a["stats"][k]}</td>'
        f'<td class="num">{a["stats"][k] - b["stats"][k]:+d}</td></tr>'
        for k in b["stats"]
    )
    sections = []
    for key, s in d["sections"].items():
        count = len(s["added"]) + len(s["removed"]) + len(s.get("changed", []))
        body = (
            f'<div class="wrap"><table><thead><tr><th scope="col">Change</th><th scope="col">Item</th>'
            f'<th scope="col">Detail</th></tr></thead><tbody>{_rows(s)}</tbody></table></div>'
            if count
            else '<p class="muted" style="margin:0;padding:6px 14px 12px">No difference.</p>'
        )
        sections.append(
            f"<details{' open' if count else ''}><summary><h2>{NAMES[key]}</h2>"
            f'<span class="pill">+{len(s["added"])} / −{len(s["removed"])}'
            f"{' / ~' + str(len(s['changed'])) if s.get('changed') else ''}</span></summary>{body}</details>"
        )
    verdict = ""
    if d["integrity"]["before"] != d["integrity"]["after"]:
        verdict = (
            f'<p class="card">Recording verdict changed: {esc(d["integrity"]["before"])} '
            f"→ {esc(d['integrity']['after'])}</p>"
        )
    title = "tracewatch diff: " + (a["cmdline"] or a["id"])[:80]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="dark light">
<meta name="generator" content="tracewatch {esc(__version__)}">
<title>{esc(title)}</title>
<style nonce="{nonce}">
{_tokens()}
{PAGE_CSS}
</style>
</head>
<body>
<main>
<h1>tracewatch diff</h1>
<div class="runs">{run_card("Before", b)}{run_card("After", a)}</div>
{banner}
{notable}
{verdict}
<details open><summary><h2>Totals</h2></summary><div class="wrap"><table><thead><tr><th scope="col"></th>
<th scope="col" class="num">Before</th><th scope="col" class="num">After</th><th scope="col" class="num">Change</th></tr></thead>
<tbody>{totals}</tbody></table></div></details>
{"".join(sections)}
</main>
</body>
</html>
"""

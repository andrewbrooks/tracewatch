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
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--text); font: 14px/1.5 var(--font);
  background-image: radial-gradient(1100px 460px at 75% -8%, var(--glow-a), transparent 60%),
                    radial-gradient(800px 380px at 0% 0%, var(--glow-b), transparent 55%); }
body::before { content: ""; display: block; height: 2px; background: linear-gradient(90deg, var(--brand), transparent 45%); }
main { max-width: 1120px; margin: 0 auto; padding: 26px 20px 64px; }
h1 { font-size: 12px; letter-spacing: .22em; text-transform: uppercase; margin: 0 0 14px; font-weight: 700; }
h1 small { color: var(--text-3); letter-spacing: .12em; font-weight: 500; margin-left: 10px; }
h2 { font-size: 15px; margin: 0; }
.mono { font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }
.muted { color: var(--text-3); } .num { font-variant-numeric: tabular-nums; }
.k { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--text-3); }
.panel { background: var(--raised); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow-card); }

.runs { display: grid; grid-template-columns: 1fr auto 1fr; gap: 12px; align-items: stretch; margin: 0 0 14px; }
.run { padding: 12px 14px; border-top: 2px solid var(--line-2); } .run.after { border-top-color: var(--accent); }
.run .mono { margin: 4px 0; } .arrow { align-self: center; color: var(--text-3); font-size: 22px; }

.hero { display: grid; grid-template-columns: auto 1fr; gap: 6px 18px; align-items: center; padding: 18px 20px;
  border-left: 5px solid var(--sev-info); margin: 0 0 14px; }
.hero.ok { border-left-color: var(--good); } .hero.warn { border-left-color: var(--warning); }
.hero.danger { border-left-color: var(--critical); }
.glyph { grid-row: span 2; width: 52px; height: 52px; border-radius: 14px; display: grid; place-items: center;
  font-size: 26px; font-weight: 700; border: 1px solid var(--line-2); background: var(--raised-2); }
.ok .glyph { color: var(--t-good); } .warn .glyph { color: var(--t-warning); } .danger .glyph { color: var(--t-critical); }
.hero-title { font-size: 22px; font-weight: 700; margin: 0; letter-spacing: -.01em; }
.chips { display: flex; flex-wrap: wrap; gap: 7px; grid-column: 2; margin-top: 4px; }
.chip { display: inline-flex; gap: 6px; align-items: baseline; border: 1px solid var(--line-2); border-radius: 99px;
  padding: 2px 11px; font-size: 12.5px; background: var(--raised-2); }
.chip b { font-variant-numeric: tabular-nums; }
.chip.sev-high, .sev.sev-high { color: var(--t-critical); border-color: var(--t-critical); }
.chip.sev-medium, .sev.sev-medium { color: var(--t-serious); border-color: var(--t-serious); }
.chip.sev-low, .sev.sev-low { color: var(--t-warning); border-color: var(--t-warning); }
.chip.sev-info, .sev.sev-info { color: var(--text-2); }
.chip.proxy { color: var(--t-critical); border-color: var(--t-critical); }

.grid2 { display: grid; grid-template-columns: 1.25fr 1fr; gap: 14px; margin: 0 0 14px; align-items: start; }
.sect-title { font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--text-3); margin: 0 0 10px;
  font-weight: 600; }
.notable { list-style: none; margin: 0; padding: 14px 16px; }
.notable li { display: grid; grid-template-columns: 74px 1fr; gap: 10px; padding: 5px 0; border-top: 1px solid var(--line);
  overflow-wrap: anywhere; } .notable li:first-child { border-top: 0; }
.kind { font-size: 10.5px; font-weight: 700; letter-spacing: .07em; text-align: center; border-radius: 5px; padding: 2px 0;
  height: fit-content; border: 1px solid var(--line-2); color: var(--text-2); }
.kind.k-proxy, .kind.k-finding { color: var(--t-critical); border-color: var(--t-critical); }
.kind.k-file { color: var(--t-warning); border-color: var(--t-warning); }
.kind.k-dest, .kind.k-cmd { color: var(--text); border-color: var(--accent); }

.map { padding: 14px 16px; }
.map .row { display: grid; grid-template-columns: 112px 1fr auto; gap: 10px; align-items: center; padding: 5px 0; }
.bar { display: grid; grid-template-columns: 1fr 1px 1fr; height: 12px; align-items: center; }
.bar .axis { background: var(--line-2); height: 18px; }
.bar .half { display: flex; height: 12px; } .bar .half.l { justify-content: flex-end; }
.bar i { display: block; height: 100%; } .bar .rm { background: var(--critical); border-radius: 4px 0 0 4px; }
.bar .ad { background: var(--good); border-radius: 0 4px 4px 0; }
.map .cnt { font-size: 12px; min-width: 96px; text-align: right; font-variant-numeric: tabular-nums; color: var(--text-2); }
.legend { display: flex; gap: 14px; font-size: 11.5px; color: var(--text-3); margin-top: 8px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 5px; vertical-align: -1px; }

.tiles { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin: 0 0 14px; }
.tile { padding: 12px 14px; } .tile .big { font-size: 26px; font-weight: 700; letter-spacing: -.02em; line-height: 1.15; }
.tile .was { color: var(--text-3); font-size: 12px; }
.delta { display: inline-block; font-size: 12px; font-weight: 600; border-radius: 99px; padding: 0 8px; margin-left: 6px;
  border: 1px solid var(--line-2); color: var(--text-2); vertical-align: 3px; }
.delta.up { color: var(--t-warning); border-color: var(--t-warning); } .delta.down { color: var(--text); border-color: var(--accent); }

nav.jump { display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 12px; }
nav.jump a { color: var(--text); text-decoration: none; border: 1px solid var(--line-2); border-radius: 99px; padding: 3px 12px;
  background: var(--raised); font-size: 12.5px; } nav.jump a:hover { background: var(--hover); }
nav.jump a:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
nav.jump a.quiet { color: var(--text-3); }

details.sec { margin: 12px 0; } details.sec > summary { cursor: pointer; padding: 11px 16px; display: flex; gap: 12px;
  align-items: center; list-style: none; } details.sec > summary::-webkit-details-marker { display: none; }
details.sec > summary::before { content: "▸"; color: var(--text-3); transition: transform .12s; }
details.sec[open] > summary::before { transform: rotate(90deg); }
.pills { display: flex; gap: 6px; margin-left: auto; }
.pill { border: 1px solid var(--line-2); border-radius: 99px; padding: 0 9px; font-size: 12px; font-variant-numeric: tabular-nums; }
.pill.a { color: var(--t-good); border-color: var(--t-good); } .pill.r { color: var(--t-critical); border-color: var(--t-critical); }
.pill.c { color: var(--t-warning); border-color: var(--t-warning); }
.empty { margin: 0; padding: 4px 16px 14px; color: var(--text-3); }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
col.c-tag { width: 112px; } col.c-detail { width: 32%; }
th, td { text-align: left; padding: 6px 14px; border-top: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: var(--text-3); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr.r-added td:first-child { box-shadow: inset 3px 0 0 var(--good); } tr.r-removed td:first-child { box-shadow: inset 3px 0 0 var(--critical); }
tr.r-changed td:first-child { box-shadow: inset 3px 0 0 var(--warning); }
tr.r-added { background: rgba(12,163,12,.055); } tr.r-removed { background: rgba(208,59,59,.06); }
tr.r-changed { background: rgba(250,178,25,.055); }
.tag { display: inline-block; font-weight: 700; font-size: 11.5px; letter-spacing: .04em; }
.t-added { color: var(--t-good); } .t-removed { color: var(--t-critical); } .t-changed { color: var(--t-warning); }
.sev { display: inline-block; border: 1px solid var(--line-2); border-radius: 99px; padding: 0 8px; font-size: 11.5px;
  font-weight: 600; margin-right: 6px; }
details.more > summary { cursor: pointer; padding: 8px 16px; color: var(--text); text-decoration: underline; border-top: 1px solid var(--line);
  font-size: 12.5px; }
.wrap { overflow-x: auto; }
@media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } .tiles { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 700px) { .runs { grid-template-columns: 1fr; } .arrow { display: none; } main { padding: 18px 12px 40px; }
  .tiles { grid-template-columns: repeat(2, 1fr); } .map .row { grid-template-columns: 90px 1fr; } .map .cnt { grid-column: 2; text-align: left; }
  col.c-detail { width: 40%; } .notable li { grid-template-columns: 60px 1fr; } }
@media print { details.sec { break-inside: avoid; } body { background: #fff; color: #000; } }
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


SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SHOWN_ROWS = 10  # rows visible before "Show N more"
KINDS = (  # (prefix or fragment of a `notable` line, label, css class)
    ("now bypasses the proxy", "PROXY", "k-proxy"),
    ("(BYPASSED THE PROXY)", "PROXY", "k-proxy"),
    ("new destination", "DEST", "k-dest"),
    ("finding", "FINDING", "k-finding"),
    ("file activity", "FILE", "k-file"),
    ("new command", "CMD", "k-cmd"),
    ("trustworthiness", "TRUST", "k-finding"),
)


def _kind(note: str) -> tuple[str, str]:
    for frag, label, cls in KINDS:
        if frag in note:
            return label, cls
    return "CHANGE", ""


def _detail(it: dict) -> str:
    """The side columns of one added/removed item; a severity becomes a coloured pill (text, so never colour alone)."""
    sev = it.get("severity")
    extra = ", ".join(
        f"{k}={_short(v)}" for k, v in it.items() if k not in ("key", "severity") and v not in (None, "", [], {})
    )
    pill = f'<span class="sev sev-{esc(sev)}">{esc(sev)}</span>' if sev in SEV_ORDER else ""
    return f'{pill}<span class="muted">{esc(extra)}</span>'


def _row_list(key: str, section: dict) -> list[str]:
    out = []
    for tag, label, sign in (("added", "ADDED", "+"), ("removed", "REMOVED", "−")):
        items = section[tag]
        if key == "findings":  # the serious ones first
            items = sorted(items, key=lambda it: (SEV_ORDER.get(it.get("severity"), 9), it["key"]))
        for it in items:
            out.append(
                f'<tr class="r-{tag}"><td><span class="tag t-{tag}"><span aria-hidden="true">{sign}</span> {label}</span></td>'
                f'<td class="mono">{esc(it["key"])}</td><td>{_detail(it)}</td></tr>'
            )
    for it in section.get("changed", []):
        delta = "; ".join(f"{k}: {_short(v[0])} → {_short(v[1])}" for k, v in it["delta"].items())
        out.append(
            '<tr class="r-changed"><td><span class="tag t-changed"><span aria-hidden="true">~</span> CHANGED</span></td>'
            f'<td class="mono">{esc(it["key"])}</td><td>{esc(delta)}</td></tr>'
        )
    return out


THEAD = (
    '<colgroup><col class="c-tag"><col><col class="c-detail"></colgroup><thead><tr><th scope="col">Change</th>'
    '<th scope="col">Item</th><th scope="col">Detail</th></tr></thead>'
)


def _table(rows: list[str]) -> str:
    """The first rows in a table; any further rows behind a native <details> (no script needed)."""
    head, rest = rows[:SHOWN_ROWS], rows[SHOWN_ROWS:]
    out = f'<div class="wrap"><table>{THEAD}<tbody>{"".join(head)}</tbody></table></div>'
    if rest:
        out += (
            f'<details class="more"><summary>Show {len(rest)} more</summary><div class="wrap"><table>{THEAD}'
            f"<tbody>{''.join(rest)}</tbody></table></div></details>"
        )
    return out


def _count(s: dict) -> int:
    return len(s["added"]) + len(s["removed"]) + len(s.get("changed", []))


def _hero(d: dict, n_changes: int) -> str:
    fnd, dest = d["sections"]["findings"], d["sections"]["destinations"]
    sev = {k: 0 for k in SEV_ORDER}
    for f in fnd["added"]:
        if f.get("severity") in sev:
            sev[f["severity"]] += 1
    bypass = sum(1 for x in dest["added"] if x.get("via") == "direct") + sum(
        1 for x in dest.get("changed", []) if "via" in x["delta"] and x["delta"]["via"][1] == "direct"
    )
    worse = d["integrity"]["worse"]
    chips = [
        f'<span class="chip sev-{k}"><b>{n}</b> new {k} finding{"s" if n != 1 else ""}</span>'
        for k, n in sev.items()
        if n
    ]
    if bypass:
        chips.append(
            f'<span class="chip proxy"><b>{bypass}</b> {"destinations bypass" if bypass != 1 else "destination bypasses"} the proxy</span>'
        )
    if worse:
        chips.append('<span class="chip sev-high">recording got less trustworthy</span>')
    if d["changed"]:
        level = "danger" if (sev["high"] or bypass or worse) else "warn"
        areas = sum(1 for s in d["sections"].values() if _count(s))
        title, glyph = "Behaviour changed", "Δ"
        sub = f"{n_changes} difference{'s' if n_changes != 1 else ''} across {areas} area{'s' if areas != 1 else ''}"
    else:
        level, title, glyph = "ok", "No behavioural change", "✓"
        sub = "same commands, destinations, requests, files and findings"
    return (
        f'<section class="panel hero {level}" aria-label="Verdict"><div class="glyph" aria-hidden="true">{glyph}</div>'
        f'<div><p class="hero-title">{title}</p><span class="muted">{sub}</span></div>'
        f'<div class="chips">{"".join(chips)}</div></section>'
    )


def render(d: dict) -> str:
    from . import __version__

    nonce = secrets.token_urlsafe(18)
    b, a = d["before"], d["after"]
    n_changes = sum(_count(s) for s in d["sections"].values())
    widths: set[int] = set()  # bar widths needed -> one CSS class each (the CSP forbids inline style attributes)

    def run_card(label: str, cls: str, r: dict) -> str:
        return (
            f'<div class="panel run {cls}"><div class="k">{label}</div><div class="mono">{esc(r["cmdline"])}</div>'
            f'<div class="muted">run {esc(r["id"])} · {esc(VERDICT_LABEL.get(r["verdict"], r["verdict"]))} · '
            f"{r['duration_ns'] / 1e9:.1f}s</div></div>"
        )

    notable = ""
    if d["notable"]:
        shown = d["notable"][:15]
        items = "".join(
            f'<li><span class="kind {cls}">{label}</span><span>{esc(n)}</span></li>'
            for n, (label, cls) in ((n, _kind(n)) for n in shown)
        )
        more = (
            f'<li><span class="kind">MORE</span><span class="muted">…and {len(d["notable"]) - 15} more '
            "(see the sections below)</span></li>"
            if len(d["notable"]) > 15
            else ""
        )
        notable = f'<section class="panel" aria-label="What changed"><ul class="notable">{items}{more}</ul></section>'
    peak = max([1] + [max(len(s["added"]), len(s["removed"])) for s in d["sections"].values()])
    rows = []
    for key, s in d["sections"].items():
        na, nr, nc = len(s["added"]), len(s["removed"]), len(s.get("changed", []))
        wa, wr = round(na / peak * 100), round(nr / peak * 100)
        widths |= {wa, wr}
        rows.append(
            f'<div class="row"><span>{NAMES[key]}</span><span class="bar" aria-hidden="true">'
            f'<span class="half l"><i class="rm bw{wr}"></i></span><span class="axis"></span>'
            f'<span class="half"><i class="ad bw{wa}"></i></span></span>'
            f'<span class="cnt">+{na} / −{nr}{f" / ~{nc}" if nc else ""}</span></div>'
        )
    change_map = (
        '<section class="panel map" aria-label="Where the changes are"><p class="sect-title">Where it changed</p>'
        f'{"".join(rows)}<div class="legend"><span><i class="lg-rm"></i>removed</span>'
        '<span><i class="lg-ad"></i>added</span></div></section>'
    )
    tiles = ""
    for k in b["stats"]:
        was, now = b["stats"][k], a["stats"][k]
        diff = now - was
        cls = "up" if diff > 0 else "down" if diff < 0 else ""
        sign = f'<span class="delta {cls}">{diff:+d}</span>' if diff else '<span class="delta">no change</span>'
        tiles += (
            f'<div class="panel tile"><div class="k">{esc(k.replace("_", " "))}</div>'
            f'<div class="big num">{now}{sign}</div><div class="was num">was {was}</div></div>'
        )
    nav, sections = [], []
    for key, s in d["sections"].items():
        count = _count(s)
        quiet = "" if count else ' class="quiet"'
        nav.append(f'<a href="#sec-{key}"{quiet}>{NAMES[key]} <span class="num">{count}</span></a>')
        body = _table(_row_list(key, s)) if count else '<p class="empty">No difference.</p>'
        pills = f'<span class="pill a">+{len(s["added"])}</span><span class="pill r">−{len(s["removed"])}</span>' + (
            f'<span class="pill c">~{len(s["changed"])}</span>' if s.get("changed") else ""
        )
        sections.append(
            f'<details class="panel sec" id="sec-{key}"{" open" if count else ""}><summary><h2>{NAMES[key]}</h2>'
            f'<span class="pills">{pills}</span></summary>{body}</details>'
        )
    verdict = ""
    if d["integrity"]["before"] != d["integrity"]["after"]:
        verdict = (
            f'<p class="panel run">Recording verdict changed: {esc(d["integrity"]["before"])} '
            f"→ {esc(d['integrity']['after'])}</p>"
        )
    bar_css = "".join(f".bw{w}{{width:{w}%}}" for w in sorted(widths))
    bar_css += ".lg-rm{background:var(--critical)}.lg-ad{background:var(--good)}"
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
{bar_css}
</style>
</head>
<body>
<main>
<h1>tracewatch <small>diff</small></h1>
<div class="runs">{run_card("Before", "before", b)}<div class="arrow" aria-hidden="true">→</div>{run_card("After", "after", a)}</div>
{_hero(d, n_changes)}
{verdict}
<div class="grid2">{notable}{change_map}</div>
<div class="tiles">{tiles}</div>
<nav class="jump" aria-label="Sections">{"".join(nav)}</nav>
{"".join(sections)}
</main>
</body>
</html>
"""

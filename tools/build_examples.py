"""Build the public example reports in docs/examples/ and the landing page docs/index.html.

usage: python tools/build_examples.py [--out docs]

The reports are rendered from SANITIZED copies of local example recordings (paths, user and host names and IP addresses
replaced; see tests/browser/sanitize.py) and every file is checked, before it is written, for this machine's identifying
literals. Recordings themselves are never copied anywhere: they contain traffic and stay under out/ (git-ignored).
The recordings come from tests/fixtures/demo.sh, tests/fixtures/badactor.sh and the integration scripts."""

from __future__ import annotations

import argparse
import html
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "browser"))

from sanitize import identity, leaks, sanitize  # noqa: E402

from tracewatch.diff import compare  # noqa: E402
from tracewatch.diff_html import _tokens  # noqa: E402
from tracewatch.diff_html import render as render_diff  # noqa: E402
from tracewatch.model import build  # noqa: E402
from tracewatch.report_html import render  # noqa: E402
from tracewatch.report_md import render as render_md  # noqa: E402

REPO_URL = "https://github.com/andrewbrooks/tracewatch"

# name -> (recording, title, what it is, what to try)
EXAMPLES = {
    "demo": (
        "out/demo/runs/demo",
        "Scripted demo",
        "A scripted workload against local servers: findings of every severity, a connection that bypassed the proxy, "
        "websockets, secrets that were redacted, and a dropped binary.",
        [
            "Start on the Overview: the summary, then the ribbon of notable steps.",
            "Open Process tree (3) and click a node.",
            "Open Findings (2) and expand “About this rule” on any card.",
        ],
    ),
    "simulation": (
        "out/simulation/runs/badactor",
        "A simulated intruder",
        "A harmless, local-only simulation of an attacker’s session: decoy credential theft, a reverse-shell-shaped command to a "
        "loopback listener, obfuscated payloads that only echo, curl | sh, and a process posing as a system daemon.",
        [
            "Findings (2): open the reverse-shell finding, then “Rule reference” at the bottom.",
            "Overview: hold Ctrl and scroll over the activity lanes to zoom.",
            "Click a mark in the Findings lane to open it.",
        ],
    ),
    "showcase": (
        "out/showcase/runs/showcase",
        "A real internet session",
        "git, curl and python talking to real public services (GitHub, httpbin, example.com and example.org), recorded and reported.",
        [
            "Network (7) and HTTP (8): which process talked to whom.",
            "Run (no key): how the recording was made and what can be trusted.",
        ],
    ),
    "shared_socket": (
        "out/shared_socket/runs/shared",
        "Who sent that request?",
        "One connection held by several processes (a parent and children that inherit it). The report names the process that "
        "sent each request, not just the one that opened the connection.",
        ["HTTP (8): open the /s1 request and look at “Connection opened by”."],
    ),
    "protocols": (
        "out/protocols/runs/p",
        "HTTP/2, compression and a refused certificate",
        "HTTP/2 multiplexing, gzip/deflate/brotli/zstd bodies with their secrets redacted, a client that refused the "
        "recorder’s certificate, and a connection around the proxy.",
        [
            "HTTP (8): six streams on one connection.",
            "Findings (2): the finding for the client that refused the certificate.",
        ],
    ),
}
DIFF = ("demo", "simulation")  # before, after


def load(path: str, ident: dict):
    run = ROOT / path
    if not (run / "manifest.json").exists():
        raise SystemExit(f"missing recording {run}: record it first (see the docstring of this file)")
    return sanitize(build(run), ident)


def write_checked(path: Path, text: str, ident: dict) -> None:
    bad = leaks(text, ident)
    if bad:
        raise SystemExit(f"REFUSING to write {path.name}: it still contains\n  " + "\n  ".join(bad[:10]))
    path.write_text(text)
    print(f"wrote {path.relative_to(ROOT)} ({len(text) // 1024} KB)")


def index_page(examples: list[dict]) -> str:
    esc = html.escape
    nonce = secrets.token_urlsafe(18)
    cards = []
    for e in examples:
        tries = "".join(f"<li>{esc(t)}</li>" for t in e["try"])
        links = " ".join(f'<a class="open" href="{esc(u)}">{esc(label)}</a>' for label, u in e["links"])
        cards.append(
            f'<article class="card"><h2>{esc(e["title"])}</h2><p>{esc(e["about"])}</p>'
            f'<div class="try">Things to try</div><ul>{tries}</ul><p class="links">{links}</p></article>'
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-{nonce}'; img-src 'self'; base-uri 'none'; form-action 'none'">
<meta name="color-scheme" content="dark light">
<title>tracewatch: example reports</title>
<style nonce="{nonce}">
{_tokens()}
body {{ margin: 0; background: var(--page); color: var(--text); font: 15px/1.55 var(--font); }}
main {{ max-width: 1040px; margin: 0 auto; padding: 36px 20px 64px; }}
h1 {{ font-size: 28px; margin: 0 0 6px; letter-spacing: -.01em; }} h2 {{ font-size: 17px; margin: 0 0 6px; }}
.lede {{ color: var(--text-2); max-width: 720px; margin: 0 0 22px; }}
.hero {{ width: 100%; border: 1px solid var(--line-2); border-radius: var(--radius); display: block; margin: 0 0 26px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }}
.card {{ background: var(--raised); border: 1px solid var(--line); border-radius: var(--radius); padding: 16px 18px; box-shadow: var(--shadow-card); }}
.card p {{ margin: 0 0 10px; color: var(--text-2); }} .try {{ font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--text-3); margin-top: 10px; }}
.card ul {{ margin: 4px 0 12px; padding-left: 18px; color: var(--text-2); }} .links {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 0; }}
a {{ color: var(--accent); }} a.open {{ display: inline-block; padding: 5px 12px; border: 1px solid var(--line-2); border-radius: 8px; text-decoration: none; color: var(--text); font-weight: 600; }}
a.open:hover {{ background: var(--hover); }} a:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.note {{ color: var(--text-3); font-size: 13px; margin-top: 26px; max-width: 760px; }}
</style>
</head>
<body>
<main>
<h1>tracewatch</h1>
<p class="lede">An experiment: run a command under a Linux process tracer and an intercepting HTTPS proxy, then turn the recording into a
report you can click around in. These are real reports from example runs. Each is a single self-contained HTML file with no external requests.
Everything below is from sanitized copies: paths, names and IP addresses are placeholders.</p>
<img class="hero" src="screenshots/sim-overview-dark.png" alt="The Overview of the simulated-intruder report: a summary, a ribbon of notable steps, and zoomable swim lanes of activity">
<div class="grid">
{"".join(cards)}
</div>
<p class="note">The reports follow your system’s light or dark setting (the button at the top right overrides it). Press <b>?</b> inside a report for keyboard shortcuts.
Findings are heuristics for a human to judge, not verdicts. Source and documentation: <a href="{REPO_URL}">{REPO_URL}</a>.</p>
</main>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "docs"))
    out = Path(ap.parse_args().out)
    ex = out / "examples"
    ex.mkdir(parents=True, exist_ok=True)
    (out / ".nojekyll").write_text("")  # serve the files as they are
    ident = identity()
    models, cards = {}, []
    for name, (path, title, about, tries) in EXAMPLES.items():
        models[name] = load(path, ident)
        write_checked(ex / f"{name}.html", render(models[name]), ident)
        links = [("Open the report", f"examples/{name}.html")]
        if name == "showcase":
            write_checked(ex / "showcase.md", render_md(models[name]), ident)
            links.append(("Flat Markdown version", f"{REPO_URL}/blob/main/docs/examples/showcase.md"))
        cards.append({"title": title, "about": about, "try": tries, "links": links})
    a, b = (models[k] for k in DIFF)
    write_checked(ex / "diff.html", render_diff(compare(a, b)), ident)
    cards.append(
        {
            "title": "Comparing two runs",
            "about": "What behaved differently between the scripted demo run and the simulated-intruder run, as produced by tracewatch diff.",
            "try": ["Read “What changed” first, then open each section."],
            "links": [("Open the diff", "examples/diff.html")],
        }
    )
    write_checked(out / "index.html", index_page(cards), ident)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Interactive report: ONE self-contained HTML file (no network, no external assets) rendered from the model.

Security stance: the recorded data is hostile by nature (command lines, URLs, headers, bodies). It is embedded as
JSON with every `<`, `>` and `&` escaped (it cannot close the script tag or open a comment), the page builds its DOM
with textContent only (never innerHTML), and a Content-Security-Policy with a per-render nonce forbids every network
request and every script that is not in this file."""

from __future__ import annotations

import html
import json
import secrets
from pathlib import Path

ASSETS = Path(__file__).parent / "report_assets"

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-__NONCE__'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="generator" content="tracewatch __VERSION__">
<title>__TITLE__</title>
<style>
__CSS__
</style>
</head>
<body>
<noscript><p style="font:14px sans-serif;padding:24px;color:#e8ecf1;background:#0a0d12">This report is interactive and needs JavaScript. A flat-file version: <code>tracewatch report RUN --format md</code>.</p></noscript>
<script type="application/json" id="tw-data">__DATA__</script>
<script nonce="__NONCE__">
'use strict';
(function () {
__JS__
})();
</script>
</body>
</html>
"""


def embed_json(model: dict) -> str:
    """JSON that is safe inside <script type=application/json>: ASCII only, no raw <, > or &."""
    s = json.dumps(model, ensure_ascii=True, separators=(",", ":"))
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def read_assets() -> tuple[str, str]:
    css = (ASSETS / "style.css").read_text()
    js = "\n".join(p.read_text() for p in sorted((ASSETS / "js").glob("*.js")))
    for name, text, bad in (("style.css", css, "</style"), ("js", js, "</script")):
        if bad in text.lower():
            raise ValueError(f"asset {name} contains {bad!r}, which would break out of its tag")
    return css, js


def render(model: dict) -> str:
    css, js = read_assets()
    nonce = secrets.token_urlsafe(18)
    title = "tracewatch: " + (model["run"].get("cmdline") or model["run"].get("id") or "report")[:90]
    from . import __version__

    out = TEMPLATE
    for key, val in (
        ("__NONCE__", nonce),
        ("__VERSION__", html.escape(__version__)),
        ("__TITLE__", html.escape(title.replace("\n", " "))),
        ("__CSS__", css),
        ("__JS__", js),
        ("__DATA__", embed_json(model)),  # last: data must never be scanned for placeholders
    ):
        out = out.replace(key, val)
    return out

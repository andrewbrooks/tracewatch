"""The interactive HTML report: structure, embedding, and the security invariants that keep recorded (hostile)
data from ever becoming markup or script. Browser behaviour is tested in tests/browser/run.py."""

import json
import re

import pytest
from test_model import T0, S, execev, exitev, make_run, proxy_data, tree_events

from tracewatch import report_html
from tracewatch.model import build

HOSTILE = (
    "</script><script>window.__pwned=1</script><!-- --> \"'\\u2028 <img src=x onerror=window.__pwned=2> "
    "__JS__ __DATA__ __CSS__"
)


@pytest.fixture
def model(tmp_path):
    t, f = proxy_data()
    tr = tree_events() + t + [execev(5, 110, 1, T0 + 2 * S, ["echo", HOSTILE]), exitev(5, 110, 1, T0 + 2.5 * S)]
    f[3]["path"] = "/" + HOSTILE
    f[3]["host"] = "evil" + HOSTILE
    return build(make_run(tmp_path, tr, f))


def test_document_structure_and_every_placeholder_is_filled(model):
    html = report_html.render(model)
    assert html.startswith("<!DOCTYPE html>") and "</html>" in html
    for ph in ("__NONCE__", "__VERSION__", "__TITLE__"):
        assert ph not in html.split('id="tw-data"')[0].split("</style>")[0].replace("__DATA__", "")
    nonce = re.search(r"script-src 'nonce-([^']+)'", html).group(1)
    assert html.count(f'<script nonce="{nonce}">') == 1 and len(nonce) >= 20


def test_nonce_is_fresh_per_render(model):
    a, b = report_html.render(model), report_html.render(model)
    assert re.search(r"nonce-([^']+)'", a).group(1) != re.search(r"nonce-([^']+)'", b).group(1)


def test_embedded_json_round_trips_exactly(model):
    html = report_html.render(model)
    raw = html.split('<script type="application/json" id="tw-data">')[1].split("</script>")[0]
    assert json.loads(raw) == model  # the escaping is lossless
    assert "<" not in raw and ">" not in raw and "&" not in raw  # nothing that could open or close a tag/comment


def test_hostile_data_cannot_break_out_of_the_script_element(model):
    html = report_html.render(model)
    # exactly two <script ...> elements (data + app) and two closers; the hostile </script> is neutralized
    assert len(re.findall(r"<script\b", html)) == 2 and html.lower().count("</script") == 2
    assert "<!--" not in html and "-->" not in html.replace("<noscript>", "")
    assert "window.__pwned=1" in html  # the text is there (as data), never as an element


def test_placeholders_inside_the_data_are_not_substituted(model):
    html = report_html.render(model)
    raw = html.split('id="tw-data">')[1].split("</script>")[0]
    assert "__JS__" in json.loads(raw)["processes"][-1]["cmdline"] and "__DATA__" in raw


def test_content_security_policy_forbids_network_and_foreign_scripts(model):
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', report_html.render(model)).group(1)
    assert (
        "default-src 'none'" in csp
        and "script-src 'nonce-" in csp
        and "base-uri 'none'" in csp
        and "form-action 'none'" in csp
    )
    assert "connect-src" not in csp.replace(
        "default-src 'none'", ""
    )  # falls under default-src 'none': no fetch/XHR/websocket
    assert "unsafe-eval" not in csp and "script-src 'unsafe-inline'" not in csp


def test_no_external_resource_references_anywhere(model):
    html = report_html.render(model)
    code = html.split('id="tw-data">')[0] + html.split("</script>", 1)[1]  # everything except the data blob
    assert not re.search(r"(?:src|href)\s*=\s*[\"']?https?:", code, re.I)
    assert not re.search(r"<link\b|<iframe\b|<embed\b|<object\b|@import|url\(\s*[\"']?https?:", code, re.I)
    assert (
        "fetch(" not in code and "XMLHttpRequest" not in code and "WebSocket(" not in code and "sendBeacon" not in code
    )


def test_app_source_never_parses_markup_or_evaluates_strings():
    """Static guard for the text-only-DOM invariant: these APIs turn strings into markup or code."""
    _, js = report_html.read_assets()
    for banned in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "setTimeout('",
        'setTimeout("',
        "createContextualFragment",
        "DOMParser",
        "srcdoc",
        ".href =",
        "location =",
        "location.href",
        "javascript:",
    ):
        assert banned not in js, f"{banned!r} found in the report app"
    assert "textContent" in js and "createTextNode" in js


def test_assets_cannot_close_their_own_tags():
    css, js = report_html.read_assets()
    assert "</style" not in css.lower() and "</script" not in js.lower()


def test_title_is_escaped(model):
    title = re.search(r"<title>(.*?)</title>", report_html.render(model), re.S).group(1)
    assert "<" not in title and ">" not in title


def test_cli_writes_a_private_file(tmp_path, capsys):
    from tracewatch.cli import main

    run = make_run(tmp_path, tree_events())
    out = tmp_path / "r.html"
    assert main(["report", str(run), "-o", str(out)]) == 0
    assert out.stat().st_mode & 0o777 == 0o600 and out.read_text().startswith("<!DOCTYPE html>")
    assert main(["report", str(tmp_path / "nope")]) == 2

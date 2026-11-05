"""The static HTML diff page: complete, escaped, and script-free."""

import re

from test_diff import run
from test_model import T0, S, execev, exitev

from tracewatch.diff import compare
from tracewatch.diff_html import render
from tracewatch.model import build

EVIL = "</style><script>window.__pwn=1</script><img src=x onerror=alert(1)> \"q\" 's' & <!--"


def page(tmp_path, extra=()):
    return render(compare(build(run(tmp_path, "a")), build(run(tmp_path, "b", extra))))


def test_identical_runs_say_so(tmp_path):
    out = page(tmp_path)
    assert (
        out.startswith("<!DOCTYPE html>")
        and "No behavioural change" in out
        and "t-added" not in out.split("</style>")[1]
    )


def test_changes_are_listed_with_text_labels_not_colour_alone(tmp_path):
    extra = [execev(90, 300, 1, T0 + 3 * S, ["/usr/bin/curl", "https://x.example/"]), exitev(90, 300, 1, T0 + 3.5 * S)]
    body = page(tmp_path, extra).split("</style>", 1)[1]
    assert "Behaviour changed" in body and "ADDED" in body and "/usr/bin/curl" in body
    assert "<th scope=" in body and "<summary>" in body


def test_hostile_strings_are_escaped_and_the_page_cannot_run_script(tmp_path):
    extra = [execev(91, 301, 1, T0 + 3 * S, ["/bin/echo", EVIL]), exitev(91, 301, 1, T0 + 3.5 * S)]
    out = page(tmp_path, extra)
    body = out.split("</style>", 1)[1]
    assert "<script" not in out.lower()  # not even the page itself carries one
    assert "<img" not in body and "<script" not in body and "</style" not in body
    assert "&lt;/style&gt;" in body and "&lt;script&gt;" in body
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', out).group(1)
    assert "default-src 'none'" in csp and "script-src" not in csp and "unsafe-inline" not in csp
    assert re.search(r"style-src 'nonce-[\w-]{20,}'", csp)


def test_nonce_is_fresh_and_matches_the_style_element(tmp_path):
    d = compare(build(run(tmp_path, "a")), build(run(tmp_path, "b")))
    a, b = render(d), render(d)
    na, nb = (re.search(r"<style nonce=\"([^\"]+)\"", x).group(1) for x in (a, b))
    assert na != nb and f"nonce-{na}" in a


def test_no_external_references_and_no_dark_only_literals(tmp_path):
    out = page(tmp_path)
    assert not re.search(r"(?:src|href)\s*=|https?://|@import|url\(", out, re.I)
    assert "prefers-color-scheme: light" in out and 'name="color-scheme"' in out

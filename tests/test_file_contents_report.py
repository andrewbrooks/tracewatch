"""Captured file contents in the model and the reports: attributed, complete, and unable to inject anything."""

import json
import re

import pytest
from test_model import make_run, tree_events

from tracewatch import report_html
from tracewatch.model import build
from tracewatch.report_md import _fenced, render

HOSTILE = "</script><script>window.__pwned=1</script><img src=x onerror=alert(1)> ``` ```` | # [x](javascript:alert(1))"


def with_files(tmp_path, *records):
    d = make_run(tmp_path, tree_events())
    if records:
        (d / "files.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    return d


REC = {"path": "/tmp/drop.sh", "size": 20, "sha256": "ab" * 32, "writers": [101], "binary": False, "truncated": False,
       "text": "#!/bin/sh\necho hi\n"}  # fmt: skip


def test_the_model_carries_contents_with_writers_matched_to_processes(tmp_path):
    m = build(with_files(tmp_path, REC, {"path": 5}, {"no": "path"}))  # malformed records are skipped
    assert len(m["file_contents"]) == 1
    f = m["file_contents"][0]
    bash = next(p for p in m["processes"] if p["pid"] == 101)
    assert f["path"] == "/tmp/drop.sh" and f["text"] == REC["text"] and f["writers"] == [bash["id"]]


def test_a_run_without_captured_contents_has_an_empty_list(tmp_path):
    m = build(with_files(tmp_path))
    assert m["file_contents"] == [] and m["run"]["file_capture"] is None


def test_markdown_section_shows_content_writer_and_notes(tmp_path):
    text_file = {**REC, "redacted": True, "truncated": True, "size": 99999}
    binary = {
        "path": "/tmp/b.bin",
        "size": 2008,
        "writers": [101],
        "binary": True,
        "truncated": False,
        "head_hex": "7f454c46",
    }
    sec = render(build(with_files(tmp_path, text_file, binary))).split("## File contents")[1].split("\n## ")[0]
    assert "echo hi" in sec and "bash (101)" in sec and "secrets were redacted" in sec and "only the first part" in sec
    assert "Binary file, contents not stored" in sec and "7f454c46" in sec


def test_fence_is_longer_than_any_backtick_run_in_the_content():
    for text in ("plain", "``` inside", "````` five", "a`b``c"):
        block = _fenced(text)
        fence = block[0].removesuffix("text")
        assert block[-1] == fence and len(fence) > max((len(r) for r in re.findall(r"`+", text)), default=0)
        assert not any(line.startswith(fence) for line in block[1:-1])  # nothing inside can close it


def test_hostile_content_cannot_inject_markup_into_markdown(tmp_path):
    out = render(build(with_files(tmp_path, {**REC, "text": HOSTILE + "\n```\n# fake heading\n"})))
    sec = out.split("## File contents")[1]
    fence = re.search(r"^(`{3,})text$", sec, re.M).group(1)
    inside = sec.split(fence + "text\n", 1)[1].split("\n" + fence + "\n", 1)[0]
    assert "<img" in inside and "# fake heading" in inside  # it is all INSIDE the block...
    after = sec.split("\n" + fence + "\n", 1)[1]
    assert "<img" not in after and "# fake heading" not in after  # ...and none of it leaked out


@pytest.fixture
def hostile_page(tmp_path):
    return report_html.render(build(with_files(tmp_path, {**REC, "path": "/tmp/" + HOSTILE, "text": HOSTILE})))


def test_hostile_content_cannot_break_out_of_the_html_data_block(hostile_page):
    assert len(re.findall(r"<script\b", hostile_page)) == 2 and hostile_page.lower().count("</script") == 2
    assert "window.__pwned=1" in hostile_page  # present as data, never as an element


def test_html_report_builds_the_section_from_text_nodes_only():
    from tracewatch.report_html import read_assets

    js = "".join(read_assets())
    body = js[js.index("function fileContents()") : js.index("function eventsView()")]
    assert "innerHTML" not in body and "insertAdjacentHTML" not in body and "outerHTML" not in body
    assert "class: 'code fcode'" in body and "}, f.text)" in body  # the content is a child text node of the <pre>

"""What tracewatch says when something goes wrong or is skipped. These tests check the messages are produced, that
they name the failure without quoting content, and that behavior is unchanged."""

import logging

from tracewatch import filecapture as fc
from tracewatch import join
from tracewatch.log import log_unexpected
from tracewatch.redact import Redactor

SECRET = "hunter2-do-not-log"


def test_log_unexpected_names_the_type_but_not_the_message(caplog):
    logger = logging.getLogger("tracewatch.example")
    with caplog.at_level(logging.DEBUG, logger="tracewatch"):
        try:
            raise ValueError(f"bad value {SECRET}")
        except ValueError as e:
            log_unexpected(logger, "the thing", e)
    error = next(r for r in caplog.records if r.levelno == logging.ERROR)
    assert "the thing" in error.getMessage() and "ValueError" in error.getMessage()
    assert SECRET not in error.getMessage()
    # the full traceback is there for -v
    assert any(r.levelno == logging.DEBUG and r.exc_info for r in caplog.records)


def test_log_unexpected_hides_the_traceback_by_default(caplog):
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        try:
            raise RuntimeError(SECRET)
        except RuntimeError as e:
            log_unexpected(logging.getLogger("tracewatch.example"), "x", e)
    assert [r.levelno for r in caplog.records] == [logging.ERROR]


# ---- join.load -----------------------------------------------------------------------------------------------
def _jsonl(tmp_path, *lines):
    p = tmp_path / "events.jsonl"
    p.write_bytes(b"\n".join(lines) + b"\n")
    return p


def test_load_tolerates_a_truncated_last_line_without_a_warning(tmp_path, caplog):
    path = _jsonl(tmp_path, b'{"a":1}', b'{"a":2}', b'{"a":3')
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        assert join.load(path) == [{"a": 1}, {"a": 2}]
    assert caplog.records == []


def test_load_warns_about_damage_that_is_not_the_last_line(tmp_path, caplog):
    path = _jsonl(tmp_path, b'{"a":1}', b"garbage " + SECRET.encode(), b'{"a":3}', b"more garbage", b'{"a":5}')
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        assert join.load(path) == [{"a": 1}, {"a": 3}, {"a": 5}]
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "events.jsonl" in message and "2 unparseable line(s)" in message
    assert SECRET not in message  # the file name and a count, never the line


# ---- file capture ------------------------------------------------------------------------------------------
class _NoInotify:
    def inotify_init1(self, flags):
        return -1


def test_a_file_watcher_that_cannot_start_says_so(monkeypatch, caplog):
    monkeypatch.setattr(fc.ctypes, "CDLL", lambda *a, **k: _NoInotify())
    watcher = fc.TempWatcher(roots=())
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        watcher.run()
    assert watcher.available is False and watcher.ready.is_set()
    assert any("file watcher could not start" in r.getMessage() for r in caplog.records)


def test_an_unexpected_watcher_setup_error_is_logged_without_its_message(monkeypatch, caplog):
    def boom(*a, **k):
        raise OSError(SECRET)

    monkeypatch.setattr(fc.ctypes, "CDLL", boom)
    watcher = fc.TempWatcher(roots=())
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        watcher.run()
    assert watcher.ready.is_set()
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and "OSError" in errors[0].getMessage() and SECRET not in errors[0].getMessage()


def test_a_failing_final_pass_is_recorded_and_logged(tmp_path, monkeypatch, caplog):
    cap = fc.FileCapture(Redactor(b"k" * 32), tmp_path / "files.jsonl")

    def boom(final=False):
        raise RuntimeError(SECRET)

    monkeypatch.setattr(cap, "_pass", boom)
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        cap.finish()
    assert "RuntimeError" in cap.error  # what the recorder reports, unchanged
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and SECRET not in errors[0].getMessage()

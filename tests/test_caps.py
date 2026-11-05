"""Size-cap behavior of the proxy addon's write path and the Tracee collector (no Docker needed)."""

import importlib
import io
import json
import threading

import pytest

from tracewatch import tracee


@pytest.fixture
def addon(tmp_path, monkeypatch):
    """Fresh import of proxy_addon with small caps and a temp output."""
    monkeypatch.setenv("TW_FLOWS", str(tmp_path / "flows.jsonl"))
    monkeypatch.setenv("TW_SOFT_FLOWS_BYTES", "3000")
    monkeypatch.setenv("TW_MAX_FLOWS_BYTES", "30000")
    monkeypatch.setenv("TW_FLAGS_DIR", str(tmp_path))
    monkeypatch.setenv("TW_REDACT_KEY", "6b" * 32)
    import tracewatch.proxy_addon as pa

    pa = importlib.reload(pa)
    monkeypatch.setattr(pa, "RESERVE", 4000)  # small reserve so a 30 kB cap is meaningful
    yield pa
    if pa._fd is not None:
        import os

        os.close(pa._fd)
        pa._fd = None


def lines(addon_module, tmp_path):
    return [json.loads(x) for x in (tmp_path / "flows.jsonl").read_text().splitlines()]


def test_soft_cap_disables_bodies_but_keeps_recording(addon, tmp_path):
    assert addon._bodies_allowed()
    for i in range(40):
        addon._write({"kind": "flow", "flow_id": str(i), "pad": "x" * 100})
    assert not addon._bodies_allowed()
    assert (tmp_path / "flows_soft_cap").exists()
    rec = addon._body_record({"content-type": "text/plain"}, 5, b"hello")
    assert rec["captured"] is False and rec["reason"] == "size cap: bodies disabled" and rec["size"] == 5
    recs = lines(addon, tmp_path)
    assert sum(r["kind"] == "cap_reached" and r["level"] == "soft" for r in recs) == 1  # reported exactly once


def test_hard_cap_stops_writing_leaves_marker_and_counts_drops(addon, tmp_path):
    for i in range(400):
        addon._write({"kind": "flow", "flow_id": str(i), "pad": "x" * 100})
    size = (tmp_path / "flows.jsonl").stat().st_size
    recs = lines(addon, tmp_path)
    assert size <= 30000, size
    assert sum(r["kind"] == "cap_reached" and r["level"] == "hard" for r in recs) == 1
    assert (tmp_path / "flows_hard_cap").exists()
    assert addon._dropped["flow"] > 0
    marker = next(r for r in recs if r["kind"] == "cap_reached" and r["level"] == "hard")
    assert marker["written"] <= 30000 - 4000  # the marker itself records that data stopped below the cap


def test_essential_summaries_still_fit_in_the_reserve_after_the_hard_cap(addon, tmp_path):
    for i in range(400):
        addon._write({"kind": "flow", "flow_id": str(i), "pad": "x" * 100})
    addon.done()
    recs = lines(addon, tmp_path)
    kinds = [r["kind"] for r in recs]
    assert "redaction_summary" in kinds and "cap_summary" in kinds
    summary = next(r for r in recs if r["kind"] == "cap_summary")
    assert summary["hard_hit"] and summary["dropped"]["flow"] > 0
    assert (tmp_path / "flows.jsonl").stat().st_size <= 30000


def test_oversize_record_keeps_identity_and_loses_bulk(addon, tmp_path):
    big = {
        "kind": "flow",
        "flow_id": "F",
        "conn_id": "C",
        "headers": [["x", "y" * (addon.RECORD_CAP + 10)]],
        "body": {"text": "b"},
    }
    addon._write(big)
    (rec,) = lines(addon, tmp_path)
    assert rec["flow_id"] == "F" and rec["conn_id"] == "C"
    assert "headers" not in rec and "body" not in rec and rec["oversize_dropped"] == ["headers", "body"]


def test_gzip_decode_is_bounded(addon):
    import gzip

    bomb = gzip.compress(b"A" * (addon.PROCESS_CAP * 3))
    assert len(bomb) < 10_000  # tiny on the wire, huge when expanded
    rec = addon._body_record({"content-type": "text/plain", "content-encoding": "gzip"}, len(bomb), bomb)
    assert rec["captured"] is False and "limit" in rec["reason"]
    ok = gzip.compress(b"hello VISMARK world")
    rec = addon._body_record({"content-type": "text/plain", "content-encoding": "gzip"}, len(ok), ok)
    assert rec["captured"] and "VISMARK" in rec["text"]


def test_unknown_or_big_encodings_are_described_not_stored(addon):
    rec = addon._body_record({"content-type": "text/plain", "content-encoding": "compress"}, 5, b"zzzzz")
    assert rec["captured"] is False and "not decodable" in rec["reason"]
    rec = addon._body_record(
        {"content-type": "text/plain", "content-encoding": "br"}, 10**6, b"x" * (addon._BIG_ENCODED + 1)
    )
    assert rec["captured"] is False


def test_charset_is_honored_and_bad_bytes_do_not_crash(addon):
    rec = addon._body_record({"content-type": "text/plain; charset=latin-1"}, 4, "caf\xe9".encode("latin-1"))
    assert rec["text"] == "caf\xe9"
    rec = addon._body_record({"content-type": "text/plain"}, 3, b"\xff\xfe\xfd")
    assert rec["captured"]  # replaced, not raised


# ---- collector -------------------------------------------------------------------------------
class FakeProc:
    def __init__(self, data: bytes):
        self.stdout = io.BytesIO(data)

    def poll(self):
        return 0


def run_collector(monkeypatch, tmp_path, lines_in, **kw):
    monkeypatch.setattr(tracee.subprocess, "Popen", lambda *a, **k: FakeProc(b"".join(lines_in)))
    c = tracee.Collector("r", "c", [], tmp_path / "t.jsonl", tmp_path / "t.err", **kw)
    t = threading.Thread(target=c.run)
    t.start()
    t.join(5)
    assert not t.is_alive() and c.error is None
    return c, [json.loads(x) for x in (tmp_path / "t.jsonl").read_text().splitlines()]


def ev(i):
    return (json.dumps({"eventName": "x", "i": i, "pad": "p" * 80}) + "\n").encode()


def test_collector_cap_writes_marker_drops_rest_and_drains(monkeypatch, tmp_path):
    monkeypatch.setattr(tracee, "CAP_RESERVE", 300)
    c, recs = run_collector(monkeypatch, tmp_path, [ev(i) for i in range(200)], max_bytes=5000)
    assert c.capped and c.dropped > 0 and c.dropped + c.lines == 200  # everything was read (pipe drained)
    assert sum(r.get("kind") == "cap_reached" for r in recs) == 1
    assert (tmp_path / "t.jsonl").stat().st_size <= 5000
    assert recs[-1]["kind"] == "cap_reached"


def test_collector_without_cap_keeps_everything(monkeypatch, tmp_path):
    c, recs = run_collector(monkeypatch, tmp_path, [ev(i) for i in range(50)])
    assert not c.capped and c.dropped == 0 and len(recs) == 50


def test_collector_redaction_failure_writes_placeholder_never_the_line(monkeypatch, tmp_path):
    def boom(line):
        raise RuntimeError("x")

    c, recs = run_collector(monkeypatch, tmp_path, [ev(1), ev(2)], transform=boom)
    assert c.redaction_failures == 2
    assert recs == [{"kind": "redaction_failed", "where": "tracee"}] * 2
    assert "pad" not in (tmp_path / "t.jsonl").read_text()

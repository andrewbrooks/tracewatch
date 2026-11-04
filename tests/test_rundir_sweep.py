import json
import os
import stat

import pytest

from tracewatch.procinfo import pid_alive, same_process, start_ticks
from tracewatch.rundir import EventLog, RunDir
from tracewatch.sweep import sweep


def test_run_dir_is_private_and_never_reused(tmp_path):
    run = RunDir.create(tmp_path, "r1")
    assert stat.S_IMODE(run.path.stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        RunDir.create(tmp_path, "r1")


def test_manifest_write_is_atomic_and_private(tmp_path):
    run = RunDir.create(tmp_path, "r1")
    run.write_manifest({"a": 1})
    run.write_manifest({"a": 2})
    assert run.read_manifest() == {"a": 2}
    assert not run.p("manifest.json.tmp").exists()
    assert stat.S_IMODE(run.p("manifest.json").stat().st_mode) == 0o600


def test_event_log_records_both_clocks(tmp_path):
    log = EventLog(tmp_path / "e.jsonl")
    log.emit("x", n=1)
    log.close()
    rec = json.loads((tmp_path / "e.jsonl").read_text())
    assert rec["kind"] == "x" and rec["n"] == 1 and rec["t_wall_ns"] > 0 and rec["t_mono_ns"] > 0


def test_remove_ca_private_material_keeps_public_cert(tmp_path):
    run = RunDir.create(tmp_path, "r1")
    for n in ("mitmproxy-ca.pem", "mitmproxy-ca.p12", "mitmproxy-dhparam.pem", "mitmproxy-ca-cert.pem"):
        run.p(f"ca/{n}").write_text("x")
    assert sorted(run.remove_ca_private_material()) == ["mitmproxy-ca.p12", "mitmproxy-ca.pem", "mitmproxy-dhparam.pem"]
    assert run.p("ca/mitmproxy-ca-cert.pem").exists() and not run.p("ca/mitmproxy-ca.pem").exists()


def test_process_identity_detects_recycled_pid():
    me = os.getpid()
    t = start_ticks(me)
    assert t and same_process(me, t) and pid_alive(me)
    assert not same_process(me, t + 1)  # same pid, different start time -> a different process
    assert start_ticks(2**22 + 12345) is None


def _fake_run(root, name, status, pid, ticks):
    run = RunDir.create(root, name)
    run.write_manifest({"run_id": name, "status": status, "recorder_pid": pid, "recorder_start_ticks": ticks})
    run.p("ca/mitmproxy-ca.pem").write_text("PRIVATE")
    return run


def test_sweep_aborts_dead_recorder_and_removes_ca_key(tmp_path):
    run = _fake_run(tmp_path, "dead", "running", 2**22 + 777, 1)
    assert sweep(tmp_path, log=lambda *_: None) == ["dead"]
    m = run.read_manifest()
    assert m["status"] == "aborted" and "swept" in m
    assert not run.p("ca/mitmproxy-ca.pem").exists()
    assert "swept" in run.p("events.jsonl").read_text()


def test_sweep_leaves_live_and_finished_runs_alone(tmp_path):
    live = _fake_run(tmp_path, "live", "running", os.getpid(), start_ticks(os.getpid()))
    done = _fake_run(tmp_path, "done", "finished", 2**22 + 778, 1)
    assert sweep(tmp_path, log=lambda *_: None) == []
    assert live.read_manifest()["status"] == "running" and done.read_manifest()["status"] == "finished"


def test_sweep_treats_recycled_pid_as_dead(tmp_path):
    run = _fake_run(tmp_path, "recycled", "running", os.getpid(), start_ticks(os.getpid()) + 5)
    assert sweep(tmp_path, log=lambda *_: None) == ["recycled"] and run.read_manifest()["status"] == "aborted"

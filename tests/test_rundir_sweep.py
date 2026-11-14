import json
import logging
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tracewatch import sweep as sweep_mod
from tracewatch.cli import main
from tracewatch.procinfo import pid_alive, same_process, start_ticks
from tracewatch.rundir import EventLog, RunDir
from tracewatch.sweep import sweep, sweep_runs


@pytest.fixture(autouse=True)
def no_docker(monkeypatch):
    """The sweep tests never talk to Docker; the ones that care replace these again."""
    monkeypatch.setattr(sweep_mod, "_list_containers", lambda run_id: ([], None))
    monkeypatch.setattr(sweep_mod, "_remove_container", lambda cid: None)


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


# ---- the proxy is stopped by pid, not by a command-line pattern ------------------------------------------------
@pytest.fixture
def sleeper():
    """A throw-away process standing in for an orphaned proxy. Started with extra argv so tests can give it a
    confdir argument like the real one."""
    procs = []

    def start(*extra):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", *extra], start_new_session=True)
        procs.append(proc)
        deadline = time.monotonic() + 5
        while start_ticks(proc.pid) is None and time.monotonic() < deadline:
            time.sleep(0.01)
        return proc

    yield start
    for proc in procs:
        proc.kill()
        proc.wait()


def _dead_run(root, name, **manifest_extra):
    run = _fake_run(root, name, "running", 2**22 + 901, 1)
    m = run.read_manifest()
    m.update(manifest_extra)
    run.write_manifest(m)
    return run


def _log_event(run, kind, **fields):
    log = EventLog(run.p("events.jsonl"))
    log.emit(kind, **fields)
    log.close()


def _gone(proc, timeout=5.0):
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


def test_sweep_stops_the_proxy_the_manifest_names(tmp_path, sleeper):
    proxy = sleeper()
    run = _dead_run(tmp_path, "r", mitm_pid=proxy.pid, mitm_start_ticks=start_ticks(proxy.pid))
    assert sweep(tmp_path, log=lambda *_: None) == ["r"]
    assert _gone(proxy)
    assert json.loads(run.p("events.jsonl").read_text().splitlines()[-1])["stopped_proxy"] is True


def test_sweep_leaves_a_recycled_proxy_pid_alone(tmp_path, sleeper):
    other = sleeper()  # some unrelated process that now holds the pid
    _dead_run(tmp_path, "r", mitm_pid=other.pid, mitm_start_ticks=start_ticks(other.pid) + 5)
    sweep(tmp_path, log=lambda *_: None)
    assert not _gone(other, timeout=0.5)


def test_sweep_finds_an_older_runs_proxy_with_a_relative_runs_dir(tmp_path, sleeper, monkeypatch):
    # Regression: the old `pkill -f confdir=<run path>` used the path as given. With a relative --out (the default)
    # it never matched the proxy's absolute confdir, so orphaned proxies were never stopped.
    monkeypatch.chdir(tmp_path)
    Path("runs").mkdir()
    run = _fake_run(Path("runs"), "old", "running", 2**22 + 902, 1)
    proxy = sleeper(f"confdir={run.path.resolve()}/ca")
    _log_event(run, "component_started", component="mitm", pid=proxy.pid, port=1)
    assert sweep(Path("runs"), log=lambda *_: None) == ["old"]
    assert _gone(proxy)


def test_sweep_ignores_a_pid_that_is_not_this_runs_proxy(tmp_path, sleeper):
    unrelated = sleeper("confdir=/somewhere/else/ca")
    run = _dead_run(tmp_path, "r")
    _log_event(run, "component_started", component="mitm", pid=unrelated.pid, port=1)
    sweep(tmp_path, log=lambda *_: None)
    assert not _gone(unrelated, timeout=0.5)


# ---- dry run ---------------------------------------------------------------------------------------------------
def test_dry_run_reports_but_changes_nothing(tmp_path, sleeper, monkeypatch):
    proxy = sleeper()
    run = _dead_run(tmp_path, "r", mitm_pid=proxy.pid, mitm_start_ticks=start_ticks(proxy.pid))
    monkeypatch.setattr(sweep_mod, "_list_containers", lambda run_id: (["abc123def456"], None))
    removed = []
    monkeypatch.setattr(sweep_mod, "_remove_container", lambda cid: removed.append(cid))
    lines = []
    report = sweep_runs(tmp_path, log=lines.append, dry_run=True)
    assert report.swept == ["r"] and not report.problems
    text = "\n".join(lines)
    assert (
        "would sweep dead run r" in text and "remove 1 container(s)" in text and f"stop proxy pid {proxy.pid}" in text
    )
    assert removed == []
    assert not _gone(proxy, timeout=0.5)
    assert run.read_manifest()["status"] == "running"
    assert run.p("ca/mitmproxy-ca.pem").exists() and not run.p("events.jsonl").exists()


# ---- failures are reported, not swallowed ----------------------------------------------------------------------
def test_corrupt_manifest_is_reported_and_other_runs_are_still_swept(tmp_path, caplog):
    bad = RunDir.create(tmp_path, "a-bad")
    bad.p("manifest.json").write_text("{not json")
    good = _fake_run(tmp_path, "b-good", "running", 2**22 + 903, 1)
    with caplog.at_level(logging.WARNING, logger="tracewatch"):
        report = sweep_runs(tmp_path, log=lambda *_: None)
    assert report.swept == ["b-good"] and good.read_manifest()["status"] == "aborted"
    assert len(report.problems) == 1 and "a-bad" in report.problems[0] and "not valid JSON" in report.problems[0]
    assert any("a-bad" in r.getMessage() for r in caplog.records)


def test_running_manifest_without_a_recorder_pid_is_reported(tmp_path):
    run = RunDir.create(tmp_path, "nopid")
    run.write_manifest({"status": "running"})
    report = sweep_runs(tmp_path, log=lambda *_: None)
    assert report.swept == [] and "no recorder pid" in report.problems[0]


def test_docker_being_unavailable_is_reported_but_the_run_is_still_finalized(tmp_path, monkeypatch):
    run = _fake_run(tmp_path, "r", "running", 2**22 + 904, 1)
    monkeypatch.setattr(sweep_mod, "_list_containers", lambda run_id: ([], "could not run docker (FileNotFoundError)"))
    report = sweep_runs(tmp_path, log=lambda *_: None)
    assert report.swept == ["r"] and "could not run docker" in report.problems[0]
    assert run.read_manifest()["status"] == "aborted" and not run.p("ca/mitmproxy-ca.pem").exists()


def test_a_container_that_cannot_be_removed_is_reported_and_not_counted(tmp_path, monkeypatch):
    run = _fake_run(tmp_path, "r", "running", 2**22 + 905, 1)
    monkeypatch.setattr(sweep_mod, "_list_containers", lambda run_id: (["c1", "c2"], None))
    fail_c1 = lambda cid: "docker rm c1 failed: no such container" if cid == "c1" else None  # noqa: E731
    monkeypatch.setattr(sweep_mod, "_remove_container", fail_c1)
    report = sweep_runs(tmp_path, log=lambda *_: None)
    swept_event = json.loads(run.p("events.jsonl").read_text().splitlines()[-1])
    assert swept_event["removed_containers"] == 1
    assert len(report.problems) == 1 and "c1" in report.problems[0]


# ---- the command ----------------------------------------------------------------------------------------------
def test_sweep_command_dry_run_prints_and_exits_zero(tmp_path, capsys):
    run = _fake_run(tmp_path, "r", "running", 2**22 + 906, 1)
    assert main(["sweep", "--out", str(tmp_path), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would sweep dead run r" in out and "would sweep 1 run(s)" in out
    assert run.read_manifest()["status"] == "running"


def test_sweep_command_exits_nonzero_when_something_could_not_be_cleaned_up(tmp_path, capsys, monkeypatch):
    _fake_run(tmp_path, "r", "running", 2**22 + 907, 1)
    monkeypatch.setattr(sweep_mod, "_list_containers", lambda run_id: ([], "could not run docker (FileNotFoundError)"))
    assert main(["sweep", "--out", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "swept 1 run(s)" in captured.out and "problem:" in captured.err

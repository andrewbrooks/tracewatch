"""tools/privilege_probe.py without Docker: the flag building, the search, the evaluation, and the Docker-facing code
driven against a stub `docker` executable."""

import json
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
import privilege_probe as pp

from tracewatch import tracee

ALL_EVENTS = sorted(pp.REQUIRED_EVENTS)


def logs_for(names, host_pid=None):
    lines = []
    for n in names:
        rec = {"eventName": n}
        if host_pid is not None:
            rec["hostParentProcessId"] = host_pid
        lines.append(json.dumps(rec))
    return "\n".join(lines) + "\n"


# ---- configurations ---------------------------------------------------------------------------------------------
def test_the_baseline_is_exactly_what_tracewatch_runs_today():
    # if tracee._BASE changes, this tool must be updated to match, or it would measure the wrong thing
    assert pp.BASELINE.flags() == tracee._BASE


def test_a_non_privileged_spec_drops_everything_then_adds_back():
    spec = pp.Spec(privileged=False, caps=("BPF", "PERFMON"), seccomp_unconfined=True, debugfs=False)
    flags = spec.flags()
    assert "--privileged" not in flags and "--cap-drop=ALL" in flags
    assert "--cap-add=BPF" in flags and "--cap-add=PERFMON" in flags and "--cap-add=SYS_ADMIN" not in flags
    assert "seccomp=unconfined" in flags and "apparmor=unconfined" not in flags
    assert "/sys/kernel/debug:/sys/kernel/debug" not in flags
    assert flags[0] == "--pid=host"  # the target's host pids are what scoping needs


def test_documented_starts_go_from_narrowest_to_widest():
    base, unconfined, admin = pp.documented_starts()
    assert not base.seccomp_unconfined and unconfined.seccomp_unconfined and unconfined.apparmor_unconfined
    assert "SYS_ADMIN" in admin.caps and "SYS_ADMIN" not in unconfined.caps
    assert set(pp.DOCUMENTED_CAPS) <= set(unconfined.caps)
    assert "DAC_OVERRIDE" in base.caps  # Tracee 0.24.1 does not start without it, though its docs do not list it


# ---- minimizing --------------------------------------------------------------------------------------------------
def test_minimize_keeps_what_is_needed_and_removes_the_rest():
    needed_caps = {"BPF", "PERFMON", "SYS_RESOURCE"}
    calls = []

    def passes(spec):
        calls.append(spec)
        return needed_caps <= set(spec.caps) and spec.seccomp_unconfined and spec.cgroupns_host

    start = pp.Spec(privileged=False, caps=pp.DOCUMENTED_CAPS, seccomp_unconfined=True, apparmor_unconfined=True)
    final = pp.minimize(start, passes)
    assert set(final.caps) == needed_caps
    assert final.seccomp_unconfined and final.cgroupns_host  # needed, so kept
    assert not final.apparmor_unconfined and not final.debugfs  # not needed, so removed
    assert final.read_only_rootfs and final.no_new_privileges  # harmless, so added
    assert len(calls) == len(set(calls))  # each candidate is tried once


def test_minimize_does_not_add_a_restriction_that_breaks_it():
    start = pp.Spec(privileged=False, caps=("BPF",), seccomp_unconfined=True)
    final = pp.minimize(start, lambda s: not s.read_only_rootfs)
    assert not final.read_only_rootfs and final.no_new_privileges


# ---- evaluating a run --------------------------------------------------------------------------------------------
def test_event_names_ignores_everything_that_is_not_an_event():
    logs = (
        "starting tracee\n"
        '{"eventName":"write"}\n'
        'not json {"eventName"\n'
        '{"other":1}\n'
        '{"eventName":"sched_process_exit"}\n'
    )
    assert pp.event_names(logs) == {"write", "sched_process_exit"}


def test_evaluate_passes_only_with_every_required_event_and_no_error():
    assert pp.evaluate(logs_for(ALL_EVENTS)).ok
    short = pp.evaluate(logs_for(ALL_EVENTS[1:]))
    assert not short.ok and short.missing == {ALL_EVENTS[0]}
    assert not pp.evaluate(logs_for(ALL_EVENTS), error="boom").ok


def test_first_log_line_finds_the_startup_error_not_an_event():
    assert pp.first_log_line('{"eventName":"x"}\nError: operation not permitted\n') == "Error: operation not permitted"
    assert pp.first_log_line("") == ""


# ---- the search --------------------------------------------------------------------------------------------------
def fake_probe(rules):
    """A probe that passes exactly when rules(spec) is true, and records what it was asked."""
    asked = []

    def probe(spec):
        asked.append(spec)
        ok = rules(spec)
        return pp.ProbeResult(ok=ok, missing=set() if ok else {"net_tcp_connect"})

    probe.asked = asked  # type: ignore[attr-defined]
    return probe


def test_search_stops_when_the_baseline_does_not_work():
    probe = fake_probe(lambda s: False)
    outcome = pp.search(probe, log=lambda *_: None)
    assert not outcome.baseline.ok and outcome.final is None and len(probe.asked) == 1
    assert "baseline does not work" in pp.report(outcome)


def test_search_reports_that_privileged_is_needed_when_nothing_narrower_works():
    probe = fake_probe(lambda s: s.privileged)
    outcome = pp.search(probe, log=lambda *_: None)
    assert outcome.baseline.ok and outcome.final is None
    assert len(probe.asked) == 1 + len(pp.documented_starts())  # every starting point was tried
    assert "needs --privileged" in pp.report(outcome)


def test_search_finds_the_narrowest_working_configuration():
    # works without privilege only if seccomp is unconfined and BPF + PERFMON are present
    probe = fake_probe(lambda s: s.privileged or (s.seccomp_unconfined and {"BPF", "PERFMON"} <= set(s.caps)))
    outcome = pp.search(probe, log=lambda *_: None)
    assert outcome.start is not None and outcome.start.seccomp_unconfined
    assert outcome.final is not None and set(outcome.final.caps) == {"BPF", "PERFMON"}
    text = pp.report(outcome)
    assert "A narrower configuration works" in text and "--cap-add=BPF" in text and "--privileged" not in text


# ---- the command --------------------------------------------------------------------------------------------------
def test_the_default_prints_the_plan_and_starts_nothing(monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("no process may be started without --run")

    monkeypatch.setattr(pp.subprocess, "run", boom)
    monkeypatch.setattr(pp.subprocess, "Popen", boom)
    assert pp.main([]) == 0
    out = capsys.readouterr().out
    assert "Nothing was started" in out and "--privileged" in out and tracee.IMAGE in out


def test_run_without_docker_is_a_clear_failure(monkeypatch, capsys):
    monkeypatch.setattr(pp.shutil, "which", lambda name: None)
    assert pp.main(["--run"]) == 2
    assert "docker is not installed" in capsys.readouterr().err


# ---- the Docker-facing code, against a stub docker ---------------------------------------------------------------
STUB = """#!/usr/bin/env python3
import json, os, sys
cfg = json.load(open(os.path.join(os.path.dirname(__file__), "stub.json")))
args = sys.argv[1:]
with open(cfg["log"], "a") as f:
    f.write(json.dumps(args) + "\\n")
cmd = args[0]
if cmd == "run":
    bad = [a for a in args if a in cfg.get("fail_if_flag", [])]
    if bad:
        stream = sys.stdout if cfg.get("fail_stream") == "stdout" else sys.stderr
        stream.write(cfg.get("fail_message", "failed") + "\\n")
        sys.exit(1)
elif cmd == "logs":
    name = args[1]
    events = cfg["boot_events"] if name.endswith("-boot") else cfg["main_events"]
    for e in events:
        print(json.dumps(e))
elif cmd == "inspect":
    print("false" if cfg.get("not_running") else "true")
sys.exit(0)
"""


@pytest.fixture
def stub_docker(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "docker"
    exe.write_text(STUB)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    cfg = {
        "log": str(tmp_path / "calls.jsonl"),
        "boot_events": [{"eventName": "sched_process_exec", "hostParentProcessId": 4242}],
        "main_events": [{"eventName": n} for n in ALL_EVENTS],
    }

    def configure(**changes):
        cfg.update(changes)
        (bin_dir / "stub.json").write_text(json.dumps(cfg))

    configure()
    monkeypatch.setenv("PATH", f"{bin_dir}:{__import__('os').environ['PATH']}")
    configure.calls = lambda: [json.loads(x) for x in (tmp_path / "calls.jsonl").read_text().splitlines()]  # type: ignore[attr-defined]
    return configure


def test_probe_bootstraps_the_host_pid_then_traces_that_tree_with_the_specs_flags(stub_docker):
    spec = pp.Spec(privileged=False, caps=("BPF",), seccomp_unconfined=True)
    result = pp.DockerProbe(timeout=10, flush_s=0).probe(spec)
    assert result.ok, result
    runs = [c for c in stub_docker.calls() if c[0] == "run"]
    assert len(runs) == 2
    boot, main = runs
    assert "comm=twprobe" in boot and "--cap-add=BPF" in boot and "--privileged" not in boot
    assert "tree=4242" in main and "--cap-add=BPF" in main and tracee.IMAGE in main  # scoped to the learned host pid
    assert "--label" in main and pp.LABEL in main  # so a crash can be cleaned up
    assert [c for c in stub_docker.calls() if c[0] == "rm"]  # both containers are removed afterwards


def test_probe_reports_the_docker_error_when_a_flag_is_refused(stub_docker):
    stub_docker(fail_if_flag=["--read-only"], fail_message="Error: read-only rootfs is not supported")
    result = pp.DockerProbe(timeout=10, flush_s=0).probe(pp.Spec(read_only_rootfs=True))
    assert not result.ok and "bootstrap" in result.error and "read-only rootfs" in result.error


def test_probe_reports_an_error_that_docker_wrote_to_stdout(stub_docker):
    # some docker shims (the WSL stub, for one) put their error text on stdout
    stub_docker(fail_if_flag=["--privileged"], fail_message="docker is not available here", fail_stream="stdout")
    result = pp.DockerProbe(timeout=10, flush_s=0).probe(pp.BASELINE)
    assert not result.ok and "docker is not available here" in result.error


def test_probe_fails_with_the_missing_events_when_tracee_runs_but_misses_some(stub_docker):
    stub_docker(main_events=[{"eventName": n} for n in ALL_EVENTS if n != "write"])
    result = pp.DockerProbe(timeout=10, flush_s=0).probe(pp.BASELINE)
    assert not result.ok and result.missing == {"write"} and not result.error


def test_probe_notices_a_container_that_exits_before_reporting(stub_docker):
    stub_docker(boot_events=[], not_running=True)
    result = pp.DockerProbe(timeout=10, flush_s=0).probe(pp.BASELINE)
    assert not result.ok and "bootstrap" in result.error

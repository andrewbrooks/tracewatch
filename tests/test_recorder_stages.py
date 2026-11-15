"""The recorder's supervise stage and its stage-order guard, driven with fakes (no Docker, no real target)."""

import signal

import pytest

from tracewatch import recorder, tracee
from tracewatch.rundir import EventLog, RunDir


class FakeRoot:
    """A target that is running for the first check and has exited by the second."""

    pid = 4321
    returncode = 0

    def __init__(self):
        self.polls = [None, 0]
        self.signals = []

    def poll(self):
        return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]

    def send_signal(self, sig):
        self.signals.append(sig)

    def kill(self):
        raise AssertionError("the target must not be killed in these tests")


class FakeProxy:
    returncode = None

    def poll(self):
        return None


class FakeCollector:
    capped = False
    lines = 0
    dropped = 0
    error = None

    def is_alive(self):
        return True


class FakeStdin:
    def __init__(self, tty):
        self.tty = tty

    def isatty(self):
        return self.tty


def make_recording(tmp_path, stop_signal):
    """A _Recording with just enough state for supervise(), without the constructor's side effects."""
    rec = object.__new__(recorder._Recording)
    rec.run = RunDir.create(tmp_path, "r")
    rec.ev = EventLog(rec.run.p("events.jsonl"))
    rec.flag = {"stop": stop_signal is not None, "sig": stop_signal}
    rec.collector, rec.filecap, rec.root = FakeCollector(), object(), FakeRoot()
    rec.procs = {"mitm": FakeProxy()}
    rec.m = {}
    rec.caps_hit = []
    rec.kill_deadline = []
    rec.cname = "tw-test"
    return rec


@pytest.fixture(autouse=True)
def tracee_container_is_up(monkeypatch):
    monkeypatch.setattr(tracee, "container_running", lambda name: True)


def supervise(rec, monkeypatch, tty):
    monkeypatch.setattr(recorder.sys, "stdin", FakeStdin(tty))
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    return rec.supervise()


def test_sigterm_is_forwarded_to_the_target_even_on_a_terminal(tmp_path, monkeypatch):
    rec = make_recording(tmp_path, signal.SIGTERM)
    assert supervise(rec, monkeypatch, tty=True) == 0
    assert rec.root.signals == [signal.SIGTERM]


def test_sigint_is_forwarded_when_there_is_no_terminal(tmp_path, monkeypatch):
    rec = make_recording(tmp_path, signal.SIGINT)
    supervise(rec, monkeypatch, tty=False)
    assert rec.root.signals == [signal.SIGINT]


def test_sigint_on_a_terminal_is_left_to_the_terminal(tmp_path, monkeypatch):
    # on a tty, ^C already reached the target through its process group
    rec = make_recording(tmp_path, signal.SIGINT)
    supervise(rec, monkeypatch, tty=True)
    assert rec.root.signals == []


def test_nothing_is_sent_when_no_stop_was_requested(tmp_path, monkeypatch):
    rec = make_recording(tmp_path, None)
    supervise(rec, monkeypatch, tty=False)
    assert rec.root.signals == []


def test_supervise_and_teardown_refuse_to_run_before_the_start_stages(tmp_path):
    rec = make_recording(tmp_path, None)
    assert rec._components()[2] is rec.root
    for missing in ("collector", "filecap", "root"):
        broken = make_recording(tmp_path / missing, None)
        setattr(broken, missing, None)
        with pytest.raises(RuntimeError, match="start stages"):
            broken._components()

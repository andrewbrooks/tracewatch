import subprocess

from tracewatch import recorder
from tracewatch.cli import main


def test_preflight_reports_missing_programs(monkeypatch):
    monkeypatch.setattr(recorder.shutil, "which", lambda b: None if b == "docker" else f"/usr/bin/{b}")
    assert "required program not found on PATH: docker" in recorder.preflight()


def test_preflight_reports_unreachable_daemon(monkeypatch):
    monkeypatch.setattr(recorder.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        recorder.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, b"", b"Cannot connect")
    )
    assert any("daemon is not reachable" in p for p in recorder.preflight())


def test_preflight_reports_hung_daemon(monkeypatch):
    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a, 30)

    monkeypatch.setattr(recorder.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(recorder.subprocess, "run", hang)
    assert any("timed out" in p for p in recorder.preflight())


def test_record_refuses_cleanly_and_creates_no_run_dir(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(recorder, "preflight", lambda: ["docker is on fire"])
    assert main(["record", "--out", str(tmp_path / "runs"), "--", "true"]) == recorder.EX_RECORDER_FAILED
    assert "cannot record: docker is on fire" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_record_requires_a_command(capsys):
    try:
        main(["record"])
    except SystemExit as e:
        assert e.code == 2
    assert "needs a command" in capsys.readouterr().err

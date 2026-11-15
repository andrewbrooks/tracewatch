"""Finalize runs whose recorder died without finishing, and remove what it leaked."""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .clock import stamp
from .procinfo import same_process
from .rundir import CA_DIR, CA_KEY_FILES, EventLog, RunDir

logger = logging.getLogger(__name__)

DOCKER_TIMEOUT_S = 30


@dataclass
class SweepReport:
    """What a sweep did: the runs it finalized (in a dry run, would finalize) and the problems it hit."""

    swept: list[str] = field(default_factory=list)  # run ids finalized (in a dry run: that would be)
    problems: list[str] = field(default_factory=list)  # things that could not be checked or cleaned up


# ---- effects: each is small so tests can replace it without Docker or real processes ---------------------------
def _list_containers(run_id: str) -> tuple[list[str], str | None]:
    """Ids of the containers labelled for this run, and an error message if Docker could not be asked."""
    try:
        r = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=tracewatch.run={run_id}"],
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return [], f"could not run docker ({type(e).__name__})"
    if r.returncode != 0:
        return [], f"docker ps failed: {_first_line(r.stderr or r.stdout)}"
    return r.stdout.split(), None


def _remove_container(container_id: str) -> str | None:
    """Remove one container; returns an error message, or None on success."""
    try:
        r = subprocess.run(
            ["docker", "rm", "-f", container_id], capture_output=True, text=True, timeout=DOCKER_TIMEOUT_S
        )
    except (OSError, subprocess.SubprocessError) as e:
        return f"could not run docker ({type(e).__name__})"
    return None if r.returncode == 0 else f"docker rm {container_id[:12]} failed: {_first_line(r.stderr or r.stdout)}"


def _first_line(text: str) -> str:
    return (text.strip().splitlines() or ["no error text"])[0][:200]


def _proxy_identity(manifest: dict, run: RunDir) -> tuple[int | None, int | None]:
    """The run's proxy (pid, start ticks). The manifest records both; runs made before that fall back to the pid in
    the event log, with no start time."""
    if isinstance(manifest.get("mitm_pid"), int):
        return manifest["mitm_pid"], manifest.get("mitm_start_ticks")
    events = run.p("events.jsonl")
    if events.exists():
        for line in events.read_text(errors="replace").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue  # a kill can leave a truncated last line
            started = rec.get("kind") == "component_started" and rec.get("component") == "mitm"
            if started and isinstance(rec.get("pid"), int):
                return rec["pid"], None
    return None, None


def _is_this_runs_proxy(pid: int, ticks: int | None, run: RunDir) -> bool:
    """True only for the process the recorder started. With a start time, a recycled pid cannot match. Without one,
    the pid must have this run's CA directory as its confdir argument."""
    if ticks is not None:
        return same_process(pid, ticks)
    try:
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    # Compare resolved paths: the recorder passed an absolute confdir, and the sweep may have been given a relative one.
    want = f"confdir={run.path.resolve() / CA_DIR}".encode()
    return want in argv


def _kill(pid: int) -> str | None:
    """SIGKILL a pid; returns an error message, or None (including when it has already gone)."""
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return None
    except PermissionError:
        return f"not permitted to stop proxy pid {pid}"
    return None


# ---- the sweep ------------------------------------------------------------------------------------------------
def sweep_runs(runs_root: Path, log: Callable[[str], object] = print, *, dry_run: bool = False) -> SweepReport:
    """Mark dead-recorder runs `aborted`, remove their labelled containers and their orphan proxy, and delete the
    CA private key. A run is dead if its recorder's pid is gone or was recycled (start time differs).
    With dry_run nothing is changed: `log` says what would be done."""
    report = SweepReport()
    for mp in sorted(Path(runs_root).glob("*/manifest.json")):
        try:
            m = json.loads(mp.read_text())
        except ValueError as e:
            problem = f"{mp.parent.name}: manifest.json is not valid JSON ({type(e).__name__}), so the run was skipped"
            logger.warning(problem)
            report.problems.append(problem)
            continue
        if m.get("status") != "running":
            continue
        pid = m.get("recorder_pid")
        if not isinstance(pid, int):
            problem = f"{mp.parent.name}: marked running but has no recorder pid, so the run was skipped"
            logger.warning(problem)
            report.problems.append(problem)
            continue
        if same_process(pid, m.get("recorder_start_ticks")):
            continue
        _sweep_one(RunDir(mp.parent), m, log, dry_run, report)
    return report


def _sweep_one(run: RunDir, m: dict, log: Callable[[str], object], dry_run: bool, report: SweepReport) -> None:
    problems: list[str] = []
    ids, err = _list_containers(run.run_id)
    if err:
        problems.append(err)
    proxy_pid, proxy_ticks = _proxy_identity(m, run)
    proxy_live = proxy_pid is not None and _is_this_runs_proxy(proxy_pid, proxy_ticks, run)
    key_files = [n for n in CA_KEY_FILES if run.p(f"{CA_DIR}/{n}").exists()]
    # a target left running (policy on_recorder_death=continue) is the user's process: report it, never kill it
    still = bool(m.get("root_pid")) and same_process(m["root_pid"], m.get("root_start_ticks"))

    if dry_run:
        steps = [f"remove {len(ids)} container(s)", f"stop proxy pid {proxy_pid}" if proxy_live else "no proxy to stop"]
        steps.append(f"delete {len(key_files)} CA key file(s)")
        log(f"tracewatch: would sweep dead run {run.run_id}: {', '.join(steps)}")
        if still:
            log(
                f"tracewatch: the target of {run.run_id} (pid {m['root_pid']}) is still running and would be left alone"
            )
        for p in problems:
            logger.warning("%s: %s", run.run_id, p)
        report.swept.append(run.run_id)
        report.problems += [f"{run.run_id}: {p}" for p in problems]
        return

    removed = 0
    for cid in ids:
        e = _remove_container(cid)
        if e:
            problems.append(e)
        else:
            removed += 1
    proxy_stopped = False
    if proxy_live and proxy_pid is not None:
        e = _kill(proxy_pid)
        if e:
            problems.append(e)
        else:
            proxy_stopped = True
    removed_ca = run.remove_ca_private_material()
    m.update(status="aborted", swept=stamp(), target_still_running=still)
    run.write_manifest(m)
    ev = EventLog(run.p("events.jsonl"))
    ev.emit(
        "swept",
        removed_containers=removed,
        removed_ca_files=removed_ca,
        stopped_proxy=proxy_stopped,
        cleanup_problems=problems,
        target_still_running=still,
        note="recorder died without finalizing; data after the last heartbeat is untrusted",
    )
    ev.close()
    for p in problems:
        logger.warning("%s: %s", run.run_id, p)
    report.problems += [f"{run.run_id}: {p}" for p in problems]
    if still:
        log(f"tracewatch: WARNING: the target of {run.run_id} (pid {m['root_pid']}) is STILL RUNNING, unrecorded")
    report.swept.append(run.run_id)
    log(f"tracewatch: swept dead run {run.run_id} (removed {removed} container(s))")


def sweep(runs_root: Path, log: Callable[[str], object] = print) -> list[str]:
    """Sweep and return the ids of the runs that were finalized."""
    return sweep_runs(runs_root, log).swept

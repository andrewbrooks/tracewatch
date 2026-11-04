"""Finalize runs whose recorder died without finishing, and remove what it leaked."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .clock import stamp
from .procinfo import same_process
from .rundir import EventLog, RunDir


def sweep(runs_root: Path, log=print) -> list[str]:
    """Mark dead-recorder runs `aborted`, remove their labelled containers and orphan proxy.
    A run is dead if its recorder's pid is gone or was recycled (start time differs)."""
    swept = []
    for mp in sorted(Path(runs_root).glob("*/manifest.json")):
        try:
            m = json.loads(mp.read_text())
        except ValueError:
            continue
        if m.get("status") != "running" or same_process(m["recorder_pid"], m.get("recorder_start_ticks")):
            continue
        run = RunDir(mp.parent)
        ids = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=tracewatch.run={run.run_id}"], capture_output=True, text=True
        ).stdout.split()
        for i in ids:
            subprocess.run(["docker", "rm", "-f", i], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", f"confdir={run.path}/ca"], check=False)
        removed = run.remove_ca_private_material()
        m.update(status="aborted", swept=stamp())
        run.write_manifest(m)
        ev = EventLog(run.p("events.jsonl"))
        ev.emit(
            "swept",
            removed_containers=len(ids),
            removed_ca_files=removed,
            note="recorder died without finalizing; data after the last heartbeat is untrusted",
        )
        ev.close()
        swept.append(run.run_id)
        log(f"tracewatch: swept dead run {run.run_id} (removed {len(ids)} container(s))")
    return swept

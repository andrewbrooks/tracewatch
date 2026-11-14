"""Process identity helpers (pid + start time, so a recycled pid is not mistaken for the original)."""

from __future__ import annotations

import os


def start_ticks(pid: int) -> int | None:
    """Field 22 of /proc/<pid>/stat (clock ticks since boot at process start); None if gone."""
    try:
        raw = open(f"/proc/{pid}/stat").read()
    except OSError:
        return None
    return int(raw[raw.rindex(")") + 2 :].split()[19])


def same_process(pid: int, ticks: int | None) -> bool:
    """Whether `pid` is still the same process: it exists and its start time matches `ticks`, so a recycled pid does not
    count."""
    return ticks is not None and start_ticks(pid) == ticks


def pid_alive(pid: int) -> bool:
    """Whether a process with this pid exists. One we are not permitted to signal still counts as alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True

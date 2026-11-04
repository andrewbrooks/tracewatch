"""Clock stamps. The wall clock steps on some hosts (WSL2: about +1.9 s per ~30 s against
CLOCK_MONOTONIC), and Tracee timestamps are monotonic-based, so every record carries both."""

import time


def stamp() -> dict:
    return {"t_wall_ns": time.time_ns(), "t_mono_ns": time.monotonic_ns()}

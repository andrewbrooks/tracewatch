"""Tracee (container) control: version provenance, host-pid bootstrap, scoped run, log collector."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

IMAGE = "aquasec/tracee:latest"
EVENTS = "sched_process_exec,sched_process_exit,net_tcp_connect"
_BASE = [
    "--pid=host",
    "--cgroupns=host",
    "--privileged",
    "-v",
    "/etc/os-release:/etc/os-release-host:ro",
    "-v",
    "/sys/kernel/debug:/sys/kernel/debug",
    "-e",
    "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host",
]


def image_info() -> dict:
    """Digest and reported version of the Tracee image actually used (provenance for the manifest)."""
    info = {"image": IMAGE}
    r = subprocess.run(
        ["docker", "image", "inspect", IMAGE, "--format", "{{index .RepoDigests 0}}"], capture_output=True, text=True
    )
    info["digest"] = r.stdout.strip() or None
    v = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            "/etc/os-release:/etc/os-release-host:ro",
            "-e",
            "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host",
            IMAGE,
            "version",
        ],
        capture_output=True,
        text=True,
    )
    info["version"] = (v.stdout.strip() or v.stderr.strip())[:200] or None
    return info


def docker_run(run_id: str, name: str, tracee_args: list[str]) -> None:
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--label", f"tracewatch.run={run_id}", *_BASE, IMAGE, *tracee_args],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def first_event(name: str, timeout: float = 90) -> dict | None:
    end = time.time() + timeout
    while time.time() < end:
        out = subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if '"eventName"' in line:
                return json.loads(line)
        time.sleep(0.5)
    return None


def bootstrap_host_pid(run_id: str, timeout: float = 90) -> int | None:
    """Tree scoping needs the HOST-namespace pid of the root (not the pid /proc shows). Learn it from
    a short-lived Tracee watching the probe binary the held root keeps running."""
    name = f"tw-{run_id}-boot"
    docker_run(run_id, name, ["--events", "sched_process_exec", "--scope", "comm=twprobe", "--output", "json"])
    try:
        ev = first_event(name, timeout)
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return int(ev["hostParentProcessId"]) if ev else None


def start_scoped(run_id: str, name: str, host_pid: int) -> None:
    docker_run(run_id, name, ["--events", EVENTS, "--scope", f"tree={host_pid}", "--output", "json"])


def container_running(name: str) -> bool:
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True)
    return r.stdout.strip() == "true"


def stop_and_remove(name: str, grace: int = 3) -> None:
    subprocess.run(["docker", "stop", "-t", str(grace), name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def remove(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Collector(threading.Thread):
    """Pumps `docker logs -f <container>` into tracee.jsonl, one os.write per complete line.
    The child is tied to our life with PDEATHSIG so a recorder crash cannot leave a stray follower."""

    def __init__(self, container: str, out: Path, err: Path):
        super().__init__(daemon=True, name="tracee-collector")
        self.container, self.out, self.err = container, out, err
        self.lines = 0
        self.bytes = 0
        self.proc: subprocess.Popen | None = None
        self.error: str | None = None

    def run(self) -> None:
        try:
            self.proc = subprocess.Popen(
                ["setpriv", "--pdeathsig", "SIGKILL", "docker", "logs", "-f", self.container],
                stdout=subprocess.PIPE,
                stderr=open(self.err, "ab"),
                bufsize=0,
            )
            fd = os.open(self.out, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            last_sync = time.monotonic()
            for line in iter(self.proc.stdout.readline, b""):
                os.write(fd, line if line.endswith(b"\n") else line + b"\n")
                self.lines += 1
                self.bytes += len(line)
                if time.monotonic() - last_sync > 1:
                    os.fsync(fd)
                    last_sync = time.monotonic()
            os.fsync(fd)
            os.close(fd)
        except Exception as e:  # surfaced via .error; the recorder records the loss
            self.error = repr(e)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()

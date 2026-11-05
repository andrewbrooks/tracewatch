"""Tracee (container) control: version provenance, host-pid bootstrap, scoped run, log collector."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

IMAGE = "aquasec/tracee:latest"
CAP_RESERVE = 4096  # headroom below the cap for the marker line
EVENTS = "sched_process_exec,sched_process_exit,net_tcp_connect,security_socket_connect"

# File activity is high-volume (every process opens dozens of libraries), so only these paths are watched,
# filtered inside Tracee. Tracee's string filter supports only a PREFIX (`/tmp/*`) or a SUFFIX (`*/id_rsa`)
# wildcard, not "contains", so credential stores are matched by file name and by well-known directory.
SENSITIVE_NAMES = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", ".netrc", ".git-credentials", ".npmrc",
    ".pypirc", ".pgpass", ".env", "kubeconfig",
)  # fmt: skip
SENSITIVE_SUFFIXES = (".pem", ".p12", ".pfx", ".kdbx")
SENSITIVE_HOME_DIRS = (".ssh", ".aws", ".kube", ".gnupg", ".docker", ".config/gcloud", ".azure")
SENSITIVE_ABSOLUTE = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/*", "/root/.ssh/*", "/root/.aws/*")
STAGING_DIRS = ("/tmp/*", "/var/tmp/*", "/dev/shm/*")


def file_watch_patterns(homes: list[str] | None = None) -> list[str]:
    """The path patterns passed to Tracee's security_file_open filter (also recorded in the manifest)."""
    import os

    homes = homes if homes is not None else sorted({os.path.expanduser("~"), os.environ.get("HOME", "")} - {""})
    pats = [f"*/{n}" for n in SENSITIVE_NAMES] + [f"*{x}" for x in SENSITIVE_SUFFIXES]
    pats += list(SENSITIVE_ABSOLUTE)
    pats += [f"{h.rstrip('/')}/{d}/*" for h in homes for d in SENSITIVE_HOME_DIRS]
    pats += list(STAGING_DIRS)
    return list(dict.fromkeys(pats))


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


def container_running(name: str) -> bool:
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True)
    return r.stdout.strip() == "true"


def stop_and_remove(name: str, grace: int = 3) -> None:
    subprocess.run(["docker", "stop", "-t", str(grace), name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def remove(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scoped_args(host_pid: int, file_patterns: list[str] | None = None) -> list[str]:
    pats = file_watch_patterns() if file_patterns is None else file_patterns
    args = ["--events", EVENTS]
    if pats:
        args += ["--events", f"security_file_open.data.pathname={','.join(pats)}"]
    return args + ["--scope", f"tree={host_pid}", "--output", "json"]


class Collector(threading.Thread):
    """Runs the scoped Tracee container ATTACHED with `--log-driver none` and pumps its stdout into
    tracee.jsonl, one os.write per complete line, redacted first (`transform`).

    Why not `docker run -d` + `docker logs -f`: Docker would persist every raw event, argv with secrets
    included, in its own log store for the life of the container. With the `none` driver the only copy
    is the pipe this thread reads, so nothing unredacted is ever written anywhere.
    The docker client is tied to our life with PDEATHSIG; the container itself is not (the sweep
    removes it), but with no log driver its output is discarded once we are gone."""

    def __init__(
        self,
        run_id: str,
        container: str,
        tracee_args: list[str],
        out: Path,
        err: Path,
        transform=None,
        max_bytes: int | None = None,
    ):
        super().__init__(daemon=True, name="tracee-collector")
        self.run_id, self.container, self.tracee_args = run_id, container, tracee_args
        self.out, self.err = out, err
        self.transform = transform  # bytes line -> bytes line (redaction); applied BEFORE the write
        self.redaction_failures = 0
        self.max_bytes = max_bytes  # past this, lines are dropped (and counted) but the pipe keeps draining
        self.capped = False
        self.dropped = 0
        self.written = 0
        self.lines = 0
        self.bytes = 0
        self.proc: subprocess.Popen | None = None
        self.error: str | None = None

    def run(self) -> None:
        try:
            self.proc = subprocess.Popen(
                [
                    "setpriv",
                    "--pdeathsig",
                    "SIGKILL",
                    "docker",
                    "run",
                    "--name",
                    self.container,
                    "--label",
                    f"tracewatch.run={self.run_id}",
                    "--log-driver",
                    "none",
                    *_BASE,
                    IMAGE,
                    *self.tracee_args,
                ],
                stdout=subprocess.PIPE,
                stderr=open(self.err, "ab"),
                bufsize=0,
                start_new_session=True,  # keep terminal signals (Ctrl-C) away from the Tracee client
            )
            fd = os.open(self.out, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            last_sync = time.monotonic()
            for line in iter(self.proc.stdout.readline, b""):
                data = line if line.endswith(b"\n") else line + b"\n"
                if self.transform:
                    try:
                        data = self.transform(data)
                    except Exception:  # noqa: BLE001 - fail closed: never write a line we could not redact
                        self.redaction_failures += 1
                        data = b'{"kind":"redaction_failed","where":"tracee"}\n'
                if self.max_bytes and self.written + len(data) > self.max_bytes - CAP_RESERVE:
                    if not self.capped:
                        self.capped = True
                        marker = b'{"kind":"cap_reached","source":"tracee","limit":%d,"written":%d}\n' % (
                            self.max_bytes,
                            self.written,
                        )
                        self.written += os.write(fd, marker)
                    self.dropped += 1  # keep draining: a full pipe would block Tracee and the target's events
                    continue
                self.written += os.write(fd, data)
                self.lines += 1
                self.bytes += len(line)
                if time.monotonic() - last_sync > 1:
                    os.fsync(fd)
                    last_sync = time.monotonic()
            os.fsync(fd)
            os.close(fd)
        except Exception as e:  # noqa: BLE001 - surfaced via .error; the recorder records the loss
            self.error = repr(e)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()

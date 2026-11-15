"""Find out how much privilege the Tracee container really needs.

tracewatch starts Tracee with `--privileged` (see tracee._BASE). Tracee's documentation lists a smaller set of Linux
capabilities, but gives no worked example of using it, and says nothing about seccomp, AppArmor or /sys/kernel/debug.
This tool measures instead of guessing: it runs a small workload under Tracee with the flags tracewatch uses today,
then with narrower ones, and reports which narrower configurations still produce every event tracewatch relies on.

usage: python tools/privilege_probe.py            # print the plan; start nothing
       python tools/privilege_probe.py --run      # run the search (needs Docker; takes several minutes)

The search:
  1. The baseline (today's flags) must work, or the machine cannot run Tracee at all and nothing else is meaningful.
  2. `--privileged` is replaced by the documented capability list, first with the default seccomp and AppArmor
     profiles, then without them, then with CAP_SYS_ADMIN added. The first that works is the starting point.
  3. From there each capability and each extra flag is removed in turn, and kept out if Tracee still works.
  4. Two extra restrictions (read-only root filesystem, no-new-privileges) are added if they cause no failure.

What a pass means: the container started, scoped to a process tree the way tracewatch scopes it, and reported an
exec, an exit, a TCP connect, a socket connect, a socket write and a watched-file open from the workload. It does not
prove the full recorder works. Before changing tracewatch, run the integration scripts in tests/integration with the
chosen flags.

This starts the same privileged-capable containers tracewatch does. Everything it starts is labelled
`tracewatch.probe` and removed afterwards (and `--cleanup` removes any left behind by a crash).
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from tracewatch import tracee

LABEL = "tracewatch.probe"
# Capabilities Tracee's documentation lists for eBPF tracing (docs/install/prerequisites.md): CAP_SYS_RESOURCE for map
# limits, CAP_BPF and CAP_PERFMON on kernels >= 5.8, CAP_SYS_PTRACE for process information, CAP_NET_ADMIN for
# cgroup_skb network capture, CAP_SYSLOG for /proc/kallsyms, CAP_IPC_LOCK on some distributions, CAP_SETPCAP so
# Tracee can reduce its own capabilities after start-up.
DOCUMENTED_CAPS = ("SYS_RESOURCE", "BPF", "PERFMON", "SYS_PTRACE", "NET_ADMIN", "SYSLOG", "IPC_LOCK", "SETPCAP")
# What tracewatch needs Tracee to report for the probe workload. sendto/sendmsg/sendmmsg are also requested by
# tracewatch, but the shell workload sends with write(), so they are not required here.
REQUIRED_EVENTS = frozenset(
    {
        "sched_process_exec",
        "sched_process_exit",
        "net_tcp_connect",
        "security_socket_connect",
        "security_file_open",
        "write",
    }
)
OS_RELEASE_MOUNT = ["-v", "/etc/os-release:/etc/os-release-host:ro"]
DEBUGFS_MOUNT = ["-v", "/sys/kernel/debug:/sys/kernel/debug"]
OS_RELEASE_ENV = ["-e", "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host"]


# ---- the configurations to try ----------------------------------------------------------------------------------
@dataclass(frozen=True)
class Spec:
    """One way of starting the Tracee container. The defaults are tracewatch's flags today."""

    privileged: bool = True
    caps: tuple[str, ...] = ()  # capabilities added after dropping all; used only when not privileged
    seccomp_unconfined: bool = False
    apparmor_unconfined: bool = False
    debugfs: bool = True  # mount /sys/kernel/debug into the container
    cgroupns_host: bool = True
    read_only_rootfs: bool = False
    no_new_privileges: bool = False

    def flags(self) -> list[str]:
        """The `docker run` flags (without the image and Tracee's own arguments)."""
        out = ["--pid=host"]
        if self.cgroupns_host:
            out.append("--cgroupns=host")
        if self.privileged:
            out.append("--privileged")
        else:
            out.append("--cap-drop=ALL")
            out += [f"--cap-add={c}" for c in self.caps]
        if self.seccomp_unconfined:
            out += ["--security-opt", "seccomp=unconfined"]
        if self.apparmor_unconfined:
            out += ["--security-opt", "apparmor=unconfined"]
        if self.no_new_privileges:
            out += ["--security-opt", "no-new-privileges"]
        if self.read_only_rootfs:
            out.append("--read-only")
        out += OS_RELEASE_MOUNT
        if self.debugfs:
            out += DEBUGFS_MOUNT
        return out + OS_RELEASE_ENV

    def describe(self) -> str:
        """A short human description of what this configuration grants."""
        if self.privileged:
            return "--privileged"
        parts = [f"caps: {', '.join(self.caps) or 'none'}"]
        for flag, name in (
            (self.seccomp_unconfined, "seccomp unconfined"),
            (self.apparmor_unconfined, "apparmor unconfined"),
            (self.debugfs, "debugfs mounted"),
            (self.cgroupns_host, "host cgroup namespace"),
            (self.read_only_rootfs, "read-only rootfs"),
            (self.no_new_privileges, "no-new-privileges"),
        ):
            if flag:
                parts.append(name)
        return "; ".join(parts)


BASELINE = Spec()
# the removable pieces of a non-privileged Spec, in the order they are tried
REMOVABLE_FLAGS = ("seccomp_unconfined", "apparmor_unconfined", "debugfs", "cgroupns_host")
ADDABLE_FLAGS = ("read_only_rootfs", "no_new_privileges")


def documented_starts() -> list[Spec]:
    """Non-privileged starting points, narrowest first: the documented capabilities with Docker's default seccomp and
    AppArmor profiles, then with both unconfined, then with CAP_SYS_ADMIN added (needed on older kernels)."""
    base = Spec(privileged=False, caps=DOCUMENTED_CAPS)
    unconfined = Spec(privileged=False, caps=DOCUMENTED_CAPS, seccomp_unconfined=True, apparmor_unconfined=True)
    admin = Spec(
        privileged=False,
        caps=(*DOCUMENTED_CAPS, "SYS_ADMIN"),
        seccomp_unconfined=True,
        apparmor_unconfined=True,
    )
    return [base, unconfined, admin]


def minimize(start: Spec, passes: Callable[[Spec], bool]) -> Spec:
    """Remove capabilities and extra flags one at a time, keeping each removal that still passes, then add the extra
    restrictions that still pass. `start` must itself pass."""
    spec = start
    for cap in start.caps:
        trial = Spec(**{**spec.__dict__, "caps": tuple(c for c in spec.caps if c != cap)})
        if passes(trial):
            spec = trial
    for name in REMOVABLE_FLAGS:
        if getattr(spec, name):
            trial = Spec(**{**spec.__dict__, name: False})
            if passes(trial):
                spec = trial
    for name in ADDABLE_FLAGS:
        trial = Spec(**{**spec.__dict__, name: True})
        if passes(trial):
            spec = trial
    return spec


# ---- evaluating one run -----------------------------------------------------------------------------------------
@dataclass
class ProbeResult:
    ok: bool
    seen: set[str] = field(default_factory=set)
    missing: set[str] = field(default_factory=set)
    error: str = ""


def event_names(logs: str) -> set[str]:
    """The names of the events in a Tracee container's JSON log output; anything that is not an event is ignored."""
    names = set()
    for line in logs.splitlines():
        line = line.strip()
        if not line.startswith("{") or '"eventName"' not in line:
            continue
        try:
            names.add(json.loads(line)["eventName"])
        except (ValueError, KeyError, TypeError):
            continue
    return names


def evaluate(logs: str, error: str = "") -> ProbeResult:
    """A run passes when no error was seen and every required event was reported."""
    seen = event_names(logs)
    missing = set(REQUIRED_EVENTS - seen)
    return ProbeResult(ok=not error and not missing, seen=seen & REQUIRED_EVENTS, missing=missing, error=error)


def first_log_line(logs: str) -> str:
    """The first non-event line of a container's output, which is usually the start-up error."""
    for line in logs.splitlines():
        if line.strip() and not line.lstrip().startswith("{"):
            return line.strip()[:300]
    return ""


# ---- running one configuration against Docker -------------------------------------------------------------------
HOLDER = """#!/bin/bash
# Stands in for tracewatch's held root: loops on a probe binary until released, then does the workload.
cd "$1" || exit 1
while [ ! -e go ]; do ./twprobe; sleep 0.2; done
/bin/true                              # an exec inside the traced tree
: > "/tmp/twprobe-file-$$"             # a file opened in a watched staging directory
exec 3<>/dev/tcp/127.0.0.1/"$2"        # a TCP connect and a socket connect
echo twprobe >&3                       # a write on a socket
exec 3>&-
rm -f "/tmp/twprobe-file-$$"
"""


class DockerProbe:
    """Runs the workload under Tracee, started with a given Spec, and reports whether the events arrived."""

    def __init__(self, image: str = tracee.IMAGE, timeout: float = 90.0, flush_s: float = 3.0) -> None:
        self.image, self.timeout, self.flush_s = image, timeout, flush_s  # flush_s: wait for Tracee's last events

    def _docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", *args], capture_output=True, text=True)

    def _start(self, name: str, spec: Spec, tracee_args: list[str]) -> str:
        """Start a Tracee container; returns an error message, or an empty string."""
        r = self._docker("run", "-d", "--name", name, "--label", LABEL, *spec.flags(), self.image, *tracee_args)
        return "" if r.returncode == 0 else first_log_line(r.stderr or r.stdout) or "docker run failed"

    def _logs(self, name: str) -> str:
        r = self._docker("logs", name)
        return r.stdout + r.stderr

    def _running(self, name: str) -> bool:
        return self._docker("inspect", "-f", "{{.State.Running}}", name).stdout.strip() == "true"

    def _wait_for(self, name: str, event: str | None = None) -> tuple[str, str]:
        """Poll a container's logs until it has reported `event` (or any event). Returns (logs, error)."""
        end = time.time() + self.timeout
        logs = ""
        while time.time() < end:
            logs = self._logs(name)
            names = event_names(logs)
            if event in names if event else names:
                return logs, ""
            if not self._running(name):
                return logs, first_log_line(logs) or "the container exited before reporting an event"
            time.sleep(0.2)
        return logs, f"timed out after {self.timeout:.0f}s waiting for {event or 'the first event'}"

    def probe(self, spec: Spec) -> ProbeResult:
        """Run the workload under Tracee started with `spec`."""
        tag = uuid.uuid4().hex[:8]
        boot, main = f"tw-probe-{tag}-boot", f"tw-probe-{tag}"
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        threading.Thread(target=_accept_forever, args=(listener,), daemon=True).start()
        holder: subprocess.Popen[bytes] | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="twprobe-") as tmp:
                shutil.copy(shutil.which("true") or "/bin/true", Path(tmp) / "twprobe")
                Path(tmp, "holder.sh").write_text(HOLDER)
                holder = subprocess.Popen(["bash", str(Path(tmp) / "holder.sh"), tmp, str(listener.getsockname()[1])])
                # 1. learn the holder's host pid, as tracewatch does
                err = self._start(
                    boot, spec, ["--events", "sched_process_exec", "--scope", "comm=twprobe", "--output", "json"]
                )
                if err:
                    return evaluate("", f"bootstrap: {err}")
                logs, err = self._wait_for(boot)
                if err:
                    return evaluate(logs, f"bootstrap: {err}")
                host_pid = _host_pid(logs)
                if host_pid is None:
                    return evaluate(logs, "bootstrap: no host pid in the first event")
                # 2. trace that process tree with tracewatch's real arguments, then release the workload
                err = self._start(main, spec, tracee.scoped_args(host_pid))
                if err:
                    return evaluate("", f"scoped run: {err}")
                logs, err = self._wait_for(main, "sched_process_exec")
                if err:
                    return evaluate(logs, f"scoped run: {err}")
                Path(tmp, "go").touch()
                holder.wait(timeout=30)
                time.sleep(self.flush_s)  # let Tracee flush the last events
                return evaluate(self._logs(main))
        finally:
            if holder is not None and holder.poll() is None:
                holder.kill()
            listener.close()
            for name in (boot, main):
                self._docker("rm", "-f", name)


def _accept_forever(listener: socket.socket) -> None:
    """Accept and discard connections so the workload's connect succeeds."""
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        conn.close()


def _host_pid(logs: str) -> int | None:
    """The host-namespace pid of the probe's parent, from the first exec event."""
    for line in logs.splitlines():
        if '"eventName"' in line:
            try:
                return int(json.loads(line)["hostParentProcessId"])
            except (ValueError, KeyError, TypeError):
                continue
    return None


def cleanup() -> int:
    """Remove containers left behind by an interrupted run. Returns how many were removed."""
    r = subprocess.run(["docker", "ps", "-aq", "--filter", f"label={LABEL}"], capture_output=True, text=True)
    ids = r.stdout.split()
    for i in ids:
        subprocess.run(["docker", "rm", "-f", i], capture_output=True)
    return len(ids)


# ---- the search -------------------------------------------------------------------------------------------------
@dataclass
class Outcome:
    baseline: ProbeResult
    start: Spec | None = None
    final: Spec | None = None
    trials: list[tuple[Spec, ProbeResult]] = field(default_factory=list)


def search(passes_probe: Callable[[Spec], ProbeResult], log: Callable[[str], None] = print) -> Outcome:
    """Run the search described in the module docstring and return what was tried and what was found."""
    outcome = Outcome(baseline=passes_probe(BASELINE))
    outcome.trials.append((BASELINE, outcome.baseline))
    log(f"baseline ({BASELINE.describe()}): {_verdict(outcome.baseline)}")
    if not outcome.baseline.ok:
        return outcome

    def passes(spec: Spec) -> bool:
        result = passes_probe(spec)
        outcome.trials.append((spec, result))
        log(f"{_verdict(result):<40} {spec.describe()}")
        return result.ok

    for start in documented_starts():
        if passes(start):
            outcome.start = start
            outcome.final = minimize(start, passes)
            break
    return outcome


def _verdict(r: ProbeResult) -> str:
    if r.ok:
        return "PASS"
    if r.error:
        return f"FAIL ({r.error[:90]})"
    return f"FAIL (missing {', '.join(sorted(r.missing))})"


def plan() -> str:
    """What `--run` would do, without doing it."""
    lines = [
        f"Image: {tracee.IMAGE}",
        f"Required events: {', '.join(sorted(REQUIRED_EVENTS))}",
        "",
        "Baseline (tracewatch today):",
        "  docker run " + " ".join(BASELINE.flags()),
        "",
        "Starting points tried if the baseline passes (first that passes is minimized):",
    ]
    for s in documented_starts():
        lines.append(f"  {s.describe()}")
    lines += [
        "",
        "Then removed one at a time (kept out if Tracee still works): each capability, "
        + ", ".join(REMOVABLE_FLAGS)
        + ".",
        "Then added if they cause no failure: " + ", ".join(ADDABLE_FLAGS) + ".",
        "",
        "Nothing was started. Run with --run to do this (needs Docker; several minutes).",
    ]
    return "\n".join(lines)


def report(outcome: Outcome) -> str:
    """The result of a search, in words, with the flags to try in the full recorder."""
    if not outcome.baseline.ok:
        return (
            "The baseline does not work on this machine, so nothing narrower can be judged.\n"
            f"  {_verdict(outcome.baseline)}\n"
            "Check that Docker runs the image, the kernel has BTF (/sys/kernel/btf/vmlinux) and the host allows eBPF."
        )
    if outcome.final is None:
        return (
            "No non-privileged configuration worked: tracewatch needs --privileged on this machine.\n"
            "The documented capability sets were tried with and without Docker's default seccomp and AppArmor profiles."
        )
    f = outcome.final
    return "\n".join(
        [
            "A narrower configuration works for the probe workload:",
            f"  {f.describe()}",
            "",
            "docker run flags:",
            "  " + " ".join(f.flags()),
            "",
            "This is evidence, not proof. Put these flags in tracee._BASE on a branch and run the integration scripts in "
            "tests/integration before adopting them.",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    """Print the plan, or with --run search for the narrowest working configuration."""
    p = argparse.ArgumentParser(description="Measure how much privilege the Tracee container needs.")
    p.add_argument("--run", action="store_true", help="run the search (default: print the plan only)")
    p.add_argument("--cleanup", action="store_true", help="remove probe containers left behind by a crash, then exit")
    p.add_argument("--json", metavar="FILE", help="also write the results as JSON")
    p.add_argument("--timeout", type=float, default=90.0, help="seconds to wait for Tracee at each step (default 90)")
    a = p.parse_args(argv)
    if a.cleanup:
        print(f"removed {cleanup()} probe container(s)")
        return 0
    if not a.run:
        print(plan())
        return 0
    if shutil.which("docker") is None:
        print("privilege_probe: docker is not installed or not on PATH", file=sys.stderr)
        return 2
    prober = DockerProbe(timeout=a.timeout)
    try:
        outcome = search(prober.probe)
    finally:
        cleanup()
    print("\n" + report(outcome))
    if a.json:
        Path(a.json).write_text(
            json.dumps(
                {
                    "image": tracee.IMAGE,
                    "baseline_ok": outcome.baseline.ok,
                    "final": outcome.final.__dict__ if outcome.final else None,
                    "trials": [
                        {"spec": s.__dict__, "ok": r.ok, "missing": sorted(r.missing), "error": r.error}
                        for s, r in outcome.trials
                    ],
                },
                indent=1,
                default=list,
            )
        )
    return 0 if outcome.baseline.ok else 2


if __name__ == "__main__":
    sys.exit(main())

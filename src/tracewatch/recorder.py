"""Launch a command under Tracee (tree scope) + mitmproxy and record until the root process exits.

Lifecycle: start proxy -> start the root HELD (it only runs a probe loop) -> learn its host pid ->
start scoped Tracee + collector -> release the root (it execs the real command) -> supervise ->
root exits -> drain, stop components, delete the CA private key, finalize the manifest.
Component death is recorded in events.jsonl and the manifest, never silent; components are not
restarted. Capture is raw: no joining here (see join.py)."""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import __version__, tracee
from .clock import stamp
from .procinfo import start_ticks
from .redact import Redactor
from .rundir import CA_CERT, CA_DIR, FLOWS, MITM_LOG, TRACEE, TRACEE_ERR, EventLog, RunDir
from .sweep import sweep

WRAP = (
    'F=$1; shift; while [ ! -e "$F/p1" ]; do "$F/twprobe"; sleep 0.3; done; '
    'while [ ! -e "$F/p2" ]; do "$F/twprobe"; sleep 0.3; done; exec "$@"'
)
CA_ENV = ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO")
HEARTBEAT_S = 2.0
EX_RECORDER_FAILED = 70


@dataclass
class Options:
    argv: list[str]
    runs_root: Path
    port: int | None = None
    upstream_ca: str | None = None
    name: str | None = None
    drain_s: float = 3.0
    quiet: bool = False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def preflight() -> list[str]:
    """Problems that would make a recording impossible, found before any state is created."""
    problems = [
        f"required program not found on PATH: {b}"
        for b in ("docker", "setpriv", "bash", "cp", "pkill")
        if not shutil.which(b)
    ]
    if not (Path(sys.executable).parent / "mitmdump").exists():
        problems.append("mitmdump not found next to the Python interpreter (reinstall the project: uv sync)")
    if shutil.which("docker"):
        try:
            r = subprocess.run(["docker", "info"], capture_output=True, timeout=30)
            if r.returncode != 0:
                problems.append("the Docker daemon is not reachable (is Docker running?)")
        except subprocess.TimeoutExpired:
            problems.append("`docker info` timed out (is the Docker daemon hung?)")
    return problems


def record(o: Options) -> int:
    say = (lambda *_: None) if o.quiet else (lambda m: print(f"tracewatch: {m}", file=sys.stderr, flush=True))
    problems = preflight()
    if problems:
        for pr in problems:
            print(f"tracewatch: cannot record: {pr}", file=sys.stderr)
        return EX_RECORDER_FAILED
    os.umask(0o077)  # run directories hold captured traffic: every file we or our children create is private
    o.runs_root.mkdir(parents=True, exist_ok=True)
    sweep(o.runs_root, log=say)
    run = RunDir.create(o.runs_root, o.name)
    ev = EventLog(run.p("events.jsonl"))
    lost: list[str] = []
    redactor = Redactor()  # one key per run, shared with the proxy via its environment, never written
    import mitmproxy.version as mv

    m = {
        "run_id": run.run_id,
        "status": "running",
        "tracewatch": __version__,
        "argv": redactor.argv(o.argv),
        "cwd": os.getcwd(),
        "recorder_pid": os.getpid(),
        "recorder_start_ticks": start_ticks(os.getpid()),
        "started": stamp(),
        "lost_components": lost,
        "degraded": False,
        "versions": {"mitmproxy": mv.VERSION, "tracee": tracee.image_info()},
    }
    run.write_manifest(m)
    ev.emit("run_started")
    flag = {"stop": False, "sig": None}

    def on_signal(signum, _frame):
        flag["stop"], flag["sig"] = True, signum

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    procs: dict[str, subprocess.Popen] = {}
    cname = f"tw-{run.run_id}"
    collector: tracee.Collector | None = None
    root: subprocess.Popen | None = None

    def lose(component: str, **kw) -> None:
        if component not in lost:
            lost.append(component)
            m["degraded"] = True
            ev.emit("component_died", component=component, **kw)
            run.write_manifest(m)
            say(f"WARNING: {component} died; the recording is degraded from here on")

    def abort_start(why: str) -> int:
        ev.emit("fatal", why=why)
        say(f"cannot start: {why}")
        if root and root.poll() is None:
            root.kill()  # still in its probe loop: the user's command never ran
        for p in procs.values():
            if p.poll() is None:
                p.kill()
        if collector:
            collector.stop()
        tracee.remove(cname)
        run.remove_ca_private_material()
        m.update(status="failed_to_start", why=why, ended=stamp())
        run.write_manifest(m)
        return EX_RECORDER_FAILED

    # --- proxy
    port = o.port or _free_port()
    m["proxy_port"] = port
    from . import proxy_addon

    mitm_cmd = [
        "setpriv",
        "--pdeathsig",
        "SIGKILL",
        str(Path(sys.executable).parent / "mitmdump"),
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        str(port),
        "--set",
        f"confdir={run.p(CA_DIR)}",
        "--set",
        "flow_detail=0",  # mitm.log must not echo request URLs (they can carry secrets)
        "--set",
        "termlog_verbosity=warn",
    ]
    if o.upstream_ca:
        mitm_cmd += ["--set", f"ssl_verify_upstream_trusted_ca={o.upstream_ca}"]
    mitm_cmd += ["-s", proxy_addon.__file__]
    procs["mitm"] = subprocess.Popen(
        mitm_cmd,
        env=dict(os.environ, TW_FLOWS=str(run.p(FLOWS)), TW_REDACT_KEY=redactor.key.hex()),
        stdout=open(run.p(MITM_LOG), "ab"),
        stderr=subprocess.STDOUT,
    )
    if not _wait_port(port, 60) or not run.p(CA_CERT).exists():
        return abort_start("proxy did not come up")
    ev.emit("component_started", component="mitm", pid=procs["mitm"].pid, port=port)

    # --- held root
    subprocess.run(["cp", "/bin/true", str(run.p("flags/twprobe"))], check=True)
    px = f"http://127.0.0.1:{port}"
    ca = str(run.p(CA_CERT))
    env = dict(os.environ, HTTPS_PROXY=px, HTTP_PROXY=px, https_proxy=px, http_proxy=px)
    env.update({k: ca for k in CA_ENV})
    m["proxy_env"] = {
        "set": ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", *CA_ENV],
        "inherited_no_proxy": os.environ.get("NO_PROXY") or os.environ.get("no_proxy"),
    }
    root = subprocess.Popen(["bash", "-c", WRAP, "_", str(run.p("flags")), *o.argv], env=env)
    m["root_pid"] = root.pid
    ev.emit("root_held", pid=root.pid)
    run.write_manifest(m)

    # --- tracee
    say("starting kernel tracing (takes ~15 s)...")
    hp = tracee.bootstrap_host_pid(run.run_id)
    if hp is None:
        return abort_start("could not learn the root's host pid (is Docker up and Tracee runnable?)")
    m["root_host_pid"] = hp
    run.p("flags/p1").touch()
    collector = tracee.Collector(
        run.run_id, cname, tracee.scoped_args(hp), run.p(TRACEE), run.p(TRACEE_ERR), transform=redactor.tracee_line
    )
    collector.start()
    ev.emit("component_started", component="tracee", container=cname, host_pid=hp)
    for _ in range(180):
        if collector.lines and b'"eventName"' in run.p(TRACEE).read_bytes():
            break
        time.sleep(0.5)
    else:
        return abort_start("tracee produced no events")
    time.sleep(1)
    run.p("flags/p2").touch()  # release the root: it now execs the real command
    ev.emit("recording_armed")
    run.write_manifest(m)
    say(f"recording to {run.path}")

    # --- supervise
    seq, last_hb, last_chk = 0, 0.0, 0.0
    forwarded = False
    while root.poll() is None:
        if flag["stop"] and not forwarded:
            forwarded = True
            ev.emit("signal_received", signal=flag["sig"])
            if flag["sig"] == signal.SIGTERM or not sys.stdin.isatty():
                root.send_signal(flag["sig"])  # on a tty, ^C already reached the root directly
        if procs["mitm"].poll() is not None:
            lose("mitm", returncode=procs["mitm"].returncode)
        now = time.monotonic()
        if now - last_chk > 1 or not collector.is_alive():
            last_chk = now
            if not tracee.container_running(cname):
                lose("tracee", collector_error=collector.error)
            elif not collector.is_alive():
                lose("tracee-collector", error=collector.error)
        if now - last_hb >= HEARTBEAT_S:
            last_hb, seq = now, seq + 1
            ev.emit(
                "heartbeat",
                seq=seq,
                tracee_lines=collector.lines,
                flows_bytes=run.p(FLOWS).stat().st_size if run.p(FLOWS).exists() else 0,
            )
        time.sleep(0.2)
    rc = root.returncode
    ev.emit("root_exited", returncode=rc, signal=(-rc if rc < 0 else None), pid=root.pid)

    # --- teardown
    ev.emit("teardown_started")
    if "tracee" not in lost:
        time.sleep(o.drain_s)  # let Tracee flush its last events
        tracee.stop_and_remove(cname)
    collector.join(timeout=15)
    collector.stop()
    tracee.remove(cname)
    if procs["mitm"].poll() is None:
        procs["mitm"].terminate()
        try:
            procs["mitm"].wait(timeout=5)
        except subprocess.TimeoutExpired:
            procs["mitm"].kill()
    removed = run.remove_ca_private_material()
    ev.emit("ca_private_material_removed", files=removed)
    m.update(
        status="interrupted" if flag["stop"] else "finished",
        ended=stamp(),
        root_returncode=rc,
        degraded=bool(lost),
        redactions={"recorder": dict(redactor.counts), "tracee_lines_dropped": collector.redaction_failures},
    )
    run.write_manifest(m)
    ev.emit("run_finished", degraded=bool(lost))
    ev.close()
    say(f"run {run.run_id} {m['status']}{' (DEGRADED: lost ' + ', '.join(lost) + ')' if lost else ''}; exit code {rc}")
    return 128 - rc if rc < 0 else rc

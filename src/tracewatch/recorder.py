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
import threading
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
DRAIN_GRACE_S = 1.0  # after the root's exit event is read, keep collecting this long
EX_RECORDER_FAILED = 70


@dataclass
class Options:
    argv: list[str]
    runs_root: Path
    port: int | None = None
    upstream_ca: str | None = None
    name: str | None = None
    drain_s: float = 3.0
    # What happens to the TARGET when recording becomes untrustworthy:
    #  on_recorder_death: the recorder process itself dies (even kill -9). "stop" = the kernel sends the
    #    target SIGTERM (PDEATHSIG); "continue" = it keeps running, unrecorded and with a dead proxy.
    #  on_component_loss: the proxy or Tracee dies while the recorder lives. "continue" = keep going and
    #    mark the gap; "stop" = SIGTERM the target (SIGKILL after kill_grace_s).
    on_recorder_death: str = "stop"
    on_component_loss: str = "continue"
    kill_grace_s: float = 10.0
    max_flows_bytes: int = 256 * 1024 * 1024  # hard: the proxy stops writing
    soft_flows_bytes: int = 64 * 1024 * 1024  # soft: bodies are no longer stored
    max_tracee_bytes: int = 256 * 1024 * 1024
    body_cap: int = 8192  # stored characters per body, after redaction
    ws_max_records: int = 10000  # websocket message records per connection (the rest are only counted)
    ws_budget_chars: int = 262144  # stored websocket message text per connection
    ws_msg_cap: int = 2048  # stored characters per websocket message
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


def last_records(path: Path, kinds: set[str], tail: int = 65536) -> dict[str, dict]:
    """Newest record of each wanted kind in the last `tail` bytes of a JSONL file (the shutdown summaries)."""
    import json

    out: dict[str, dict] = {}
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - tail))
            lines = f.read().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if r.get("kind") in kinds:
            out[r["kind"]] = r
    return out


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
    # ABSOLUTE paths only: the CA bundle and every proxy variable handed to the target point inside the run directory,
    # and a target that changes directory (cd /tmp) would otherwise lose its CA and fail every TLS handshake.
    o.runs_root = Path(o.runs_root).resolve()
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
        "policy": {"on_recorder_death": o.on_recorder_death, "on_component_loss": o.on_component_loss},
        "limits": {
            "max_flows_bytes": o.max_flows_bytes,
            "soft_flows_bytes": o.soft_flows_bytes,
            "max_tracee_bytes": o.max_tracee_bytes,
            "body_cap_chars": o.body_cap,
            "ws_max_records": o.ws_max_records,
            "ws_budget_chars": o.ws_budget_chars,
            "ws_msg_cap": o.ws_msg_cap,
        },
        "lost_components": lost,
        "degraded": False,
        "versions": {"mitmproxy": mv.VERSION, "tracee": {"image": tracee.IMAGE, "pending": True}},
    }
    tracee_info: dict = {}
    info_thread = threading.Thread(target=lambda: tracee_info.update(tracee.image_info()), daemon=True)
    info_thread.start()  # a docker round-trip that nothing waits for until the manifest is rewritten after arming
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

    kill_deadline: list[float] = []  # set once the target has been asked to stop on our initiative

    def stop_target(reason: str) -> None:
        if root is None or root.poll() is not None or kill_deadline:
            return
        m["target_stopped"] = {"reason": reason, **stamp()}
        ev.emit("target_stopped", reason=reason)
        run.write_manifest(m)
        say(f"stopping the target: {reason}")
        root.send_signal(signal.SIGTERM)
        kill_deadline.append(time.monotonic() + o.kill_grace_s)

    def lose(component: str, **kw) -> None:
        if component not in lost:
            lost.append(component)
            m["degraded"] = True
            ev.emit("component_died", component=component, **kw)
            run.write_manifest(m)
            say(f"WARNING: {component} died; the recording is degraded from here on")
            if o.on_component_loss == "stop":
                stop_target(f"{component} died (policy: on-component-loss=stop)")

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
        "--set",
        "stream_large_bodies=1m",  # huge request bodies are forwarded unbuffered (and not captured)
    ]
    if o.upstream_ca:
        mitm_cmd += ["--set", f"ssl_verify_upstream_trusted_ca={o.upstream_ca}"]
    mitm_cmd += ["-s", proxy_addon.__file__]
    procs["mitm"] = subprocess.Popen(
        mitm_cmd,
        env=dict(
            os.environ,
            TW_FLOWS=str(run.p(FLOWS)),
            TW_REDACT_KEY=redactor.key.hex(),
            TW_BODY_CAP=str(o.body_cap),
            TW_WS_MAX_RECORDS=str(o.ws_max_records),
            TW_WS_BUDGET=str(o.ws_budget_chars),
            TW_WS_MSG_CAP=str(o.ws_msg_cap),
            TW_SOFT_FLOWS_BYTES=str(o.soft_flows_bytes),
            TW_MAX_FLOWS_BYTES=str(o.max_flows_bytes),
            TW_FLAGS_DIR=str(run.p("flags")),
        ),
        stdout=open(run.p(MITM_LOG), "ab"),
        stderr=subprocess.STDOUT,
        # Own session: a terminal's Ctrl-C goes to the whole foreground process group. It must reach the target
        # (and us), NOT our components, or the target's shutdown traffic would go unrecorded.
        start_new_session=True,
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
    # PDEATHSIG is kept across exec, so it still applies to the user's command after the wrapper execs it.
    # It is delivered when the recorder's thread that spawned the root dies, i.e. on any recorder death.
    guard = ["setpriv", "--pdeathsig", "SIGTERM"] if o.on_recorder_death == "stop" else []
    root = subprocess.Popen([*guard, "bash", "-c", WRAP, "_", str(run.p("flags")), *o.argv], env=env)
    m["root_pid"] = root.pid
    m["root_start_ticks"] = start_ticks(root.pid)
    ev.emit("root_held", pid=root.pid)
    run.write_manifest(m)

    # --- tracee
    say("starting kernel tracing (takes about 5-10 s)...")
    hp = tracee.bootstrap_host_pid(run.run_id)
    if hp is None:
        return abort_start("could not learn the root's host pid (is Docker up and Tracee runnable?)")
    m["root_host_pid"] = hp
    info_thread.join(timeout=30)
    m["versions"]["tracee"] = dict(tracee_info) or {"image": tracee.IMAGE, "error": "version lookup failed"}
    run.p("flags/p1").touch()
    watch = tracee.file_watch_patterns()
    m["file_watch"] = watch  # the ONLY paths whose opens are recorded: the report must say so
    collector = tracee.Collector(
        run.run_id,
        cname,
        tracee.scoped_args(hp, watch),
        run.p(TRACEE),
        run.p(TRACEE_ERR),
        transform=redactor.tracee_line,
        keep=tracee.keep_line,
        max_bytes=o.max_tracee_bytes,
    )
    collector.watch_exit_pid = root.pid
    collector.start()
    ev.emit("component_started", component="tracee", container=cname, host_pid=hp)
    for _ in range(180):
        if collector.lines and b'"eventName"' in run.p(TRACEE).read_bytes():
            break
        time.sleep(0.1)
    else:
        return abort_start("tracee produced no events")
    time.sleep(0.5)  # the probe has been seen: every hook is attached; a short margin for the rest to settle
    run.p("flags/p2").touch()  # release the root: it now execs the real command
    ev.emit("recording_armed")
    run.write_manifest(m)
    say(f"recording to {run.path}")

    # --- supervise
    seq, last_hb, last_chk = 0, 0.0, 0.0
    forwarded = False
    caps_hit: list[str] = []  # e.g. "proxy:soft", "proxy:hard", "tracee:hard": data was deliberately not kept
    m["caps_hit"] = caps_hit

    def note_caps() -> None:
        found = [f"proxy:{lv}" for lv in ("soft", "hard") if run.p(f"flags/flows_{lv}_cap").exists()]
        found += ["tracee:hard"] if collector.capped else []
        for c in found:
            if c not in caps_hit:
                caps_hit.append(c)
                ev.emit("cap_reached", cap=c)
                run.write_manifest(m)
                what = (
                    "bodies are no longer stored" if c == "proxy:soft" else "nothing more is recorded for this source"
                )
                say(f"WARNING: size cap reached ({c}); {what}. The target keeps running.")

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
        note_caps()
        if kill_deadline and now > kill_deadline[0] and root.poll() is None:
            ev.emit("target_killed", why="did not exit after SIGTERM")
            root.kill()
        if now - last_hb >= HEARTBEAT_S:
            last_hb, seq = now, seq + 1
            ev.emit(
                "heartbeat",
                seq=seq,
                tracee_lines=collector.lines,
                tracee_dropped=collector.dropped,
                flows_bytes=run.p(FLOWS).stat().st_size if run.p(FLOWS).exists() else 0,
            )
        time.sleep(0.2)
    if flag["stop"] and not forwarded:  # the signal arrived and the target exited before the loop handled it
        ev.emit("signal_received", signal=flag["sig"], handled="after the target exited")
    rc = root.returncode
    ev.emit("root_exited", returncode=rc, signal=(-rc if rc < 0 else None), pid=root.pid)

    # --- teardown
    ev.emit("teardown_started")
    if "tracee" not in lost:
        # let Tracee flush its last events: wait for the root's own exit event, then a short grace for the stragglers
        # that die with it; o.drain_s is only the ceiling if that event never arrives
        stop_at = time.monotonic() + o.drain_s
        while time.monotonic() < stop_at:
            seen = collector.exit_seen_at
            if seen is not None and time.monotonic() - seen >= DRAIN_GRACE_S:
                break
            time.sleep(0.05)
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
    note_caps()
    summaries = last_records(run.p(FLOWS), {"redaction_summary", "cap_summary"})
    removed = run.remove_ca_private_material()
    ev.emit("ca_private_material_removed", files=removed)
    m["caps"] = {
        "proxy": summaries.get("cap_summary"),  # None if the proxy was killed before its shutdown hook ran
        "tracee": {
            "capped": collector.capped,
            "lines_dropped": collector.dropped,
            "bytes_written": collector.written,
            "writes_not_to_sockets_skipped": collector.filtered,
        },
    }
    m.update(
        status="interrupted" if flag["stop"] else "finished",
        ended=stamp(),
        root_returncode=rc,
        degraded=bool(lost),
        redactions={
            "recorder": dict(redactor.counts),
            "tracee_lines_dropped": collector.redaction_failures,
            "proxy": (summaries.get("redaction_summary") or {}).get("counts"),
        },
    )
    run.write_manifest(m)
    ev.emit("run_finished", degraded=bool(lost))
    ev.close()
    say(f"run {run.run_id} {m['status']}{' (DEGRADED: lost ' + ', '.join(lost) + ')' if lost else ''}; exit code {rc}")
    return 128 - rc if rc < 0 else rc

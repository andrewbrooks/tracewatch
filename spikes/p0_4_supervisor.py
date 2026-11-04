#!/usr/bin/env python3
"""Spike p0_4 prototype recorder. Launch a command under Tracee (tree scope) + mitmproxy, record
until the root process exits, then tear down and finalize. Component death is recorded, never silent.
  run:    p0_4_supervisor.py run --run-dir D --port P --upstream-ca CA -- cmd args...
  sweep:  p0_4_supervisor.py sweep --runs-root DIR   (finalize runs whose supervisor died)"""
import argparse, glob, json, os, signal, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
now = time.time_ns
WRAP = ('F=$1; shift; while [ ! -e "$F/p1" ]; do "$F/twprobe"; sleep 0.3; done; '
        'while [ ! -e "$F/p2" ]; do "$F/twprobe"; sleep 0.3; done; exec "$@"')

class Rec:
    def __init__(s, d):
        s.d = d; s.fd = os.open(f"{d}/events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    def event(s, kind, **kw):
        os.write(s.fd, (json.dumps({"t_wall_ns": now(), "kind": kind, **kw}) + "\n").encode()); os.fsync(s.fd)

def write_manifest(d, m):
    tmp = f"{d}/manifest.json.tmp"
    with open(tmp, "w") as f:
        json.dump(m, f, indent=1); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, f"{d}/manifest.json")

def docker_run(run_id, name, extra):
    base = ["docker", "run", "-d", "--name", name, "--label", f"tracewatch.run={run_id}", "--pid=host",
            "--cgroupns=host", "--privileged", "-v", "/etc/os-release:/etc/os-release-host:ro",
            "-v", "/sys/kernel/debug:/sys/kernel/debug", "-e", "LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host",
            "aquasec/tracee:latest"]
    subprocess.run(base + extra, check=True, stdout=subprocess.DEVNULL)

def first_event(name, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        out = subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout
        for l in out.splitlines():
            if '"eventName"' in l:
                return json.loads(l)
        time.sleep(0.5)

def container_running(name):
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True)
    return r.stdout.strip() == "true"

def run(a):
    d = os.path.abspath(a.run_dir); run_id = os.path.basename(d.rstrip("/"))
    os.makedirs(f"{d}/flags"); os.makedirs(f"{d}/ca")
    open(f"{d}/supervisor.pid", "w").write(str(os.getpid()))
    rec = Rec(d); lost = []
    m = {"run_id": run_id, "status": "running", "started_ns": now(), "argv": a.cmd,
         "supervisor_pid": os.getpid(), "lost_components": lost}
    write_manifest(d, m); rec.event("run_started")
    stopping = {"flag": False, "interrupted": False}
    def on_term(*_): stopping["interrupted"] = True
    signal.signal(signal.SIGTERM, on_term); signal.signal(signal.SIGINT, on_term)

    def lose(name, **kw):
        if name not in lost:
            lost.append(name); rec.event("component_died", component=name, **kw); write_manifest(d, m)

    mitm = subprocess.Popen(
        ["setpriv", "--pdeathsig", "SIGKILL", "uvx", "--from", "mitmproxy", "mitmdump", "--listen-host", "127.0.0.1",
         "--listen-port", str(a.port), "--set", f"confdir={d}/ca", "--set", f"ssl_verify_upstream_trusted_ca={a.upstream_ca}",
         "-s", a.addon],
        env=dict(os.environ, TW_FLOWS=f"{d}/flows.jsonl"), stdout=open(f"{d}/mitm.log", "w"), stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            import socket; socket.create_connection(("127.0.0.1", a.port), 0.3).close(); break
        except OSError: time.sleep(0.5)
    else:
        rec.event("fatal", why="proxy did not start"); sys.exit(2)
    rec.event("component_started", component="mitm", pid=mitm.pid)

    ca = f"{d}/ca/mitmproxy-ca-cert.pem"
    subprocess.run(["cp", "/bin/true", f"{d}/flags/twprobe"], check=True)
    px = f"http://127.0.0.1:{a.port}"
    env = dict(os.environ, HTTPS_PROXY=px, https_proxy=px, CURL_CA_BUNDLE=ca, SSL_CERT_FILE=ca,
               REQUESTS_CA_BUNDLE=ca, NODE_EXTRA_CA_CERTS=ca)
    root = subprocess.Popen(["bash", "-c", WRAP, "_", f"{d}/flags"] + a.cmd, env=env, start_new_session=True,
                            stdout=open(f"{d}/root.out", "w"), stderr=subprocess.STDOUT)
    rec.event("root_started", pid=root.pid); m["root_pid"] = root.pid; write_manifest(d, m)

    boot = f"tw-{run_id}-boot"
    docker_run(run_id, boot, ["--events", "sched_process_exec", "--scope", "comm=twprobe", "--output", "json"])
    ev = first_event(boot); subprocess.run(["docker", "rm", "-f", boot], stdout=subprocess.DEVNULL)
    if not ev:
        rec.event("fatal", why="bootstrap tracee gave no host pid"); root.kill(); mitm.kill(); sys.exit(2)
    hp = ev["hostParentProcessId"]; m["root_host_pid"] = hp; write_manifest(d, m)
    open(f"{d}/flags/p1", "w").close()

    cname = f"tw-{run_id}"
    docker_run(run_id, cname, ["--events", "sched_process_exec,sched_process_exit,net_tcp_connect",
                               "--scope", f"tree={hp}", "--output", "json"])
    coll = subprocess.Popen(["setpriv", "--pdeathsig", "SIGKILL", "docker", "logs", "-f", cname],
                            stdout=open(f"{d}/tracee.jsonl", "wb"), stderr=open(f"{d}/tracee.err", "wb"))
    rec.event("component_started", component="tracee", container=cname, host_pid=hp)
    for _ in range(120):
        if os.path.getsize(f"{d}/tracee.jsonl") > 0 and b"eventName" in open(f"{d}/tracee.jsonl", "rb").read(): break
        time.sleep(0.5)
    time.sleep(1); open(f"{d}/flags/p2", "w").close(); rec.event("recording_armed")

    last_check = 0
    while root.poll() is None:
        if stopping["interrupted"] and not stopping["flag"]:
            stopping["flag"] = True; rec.event("interrupted"); os.killpg(root.pid, signal.SIGTERM)
        if mitm.poll() is not None: lose("mitm", returncode=mitm.returncode)
        if coll.poll() is not None or time.time() - last_check > 1:
            last_check = time.time()
            if not container_running(cname): lose("tracee", collector_rc=coll.poll())
        time.sleep(0.2)
    rc = root.returncode
    rec.event("root_exited", returncode=rc, signal=(-rc if rc < 0 else None), pid=root.pid)
    rec.event("teardown_started")
    if "tracee" not in lost:
        time.sleep(3)                                   # let Tracee flush its last events
        subprocess.run(["docker", "stop", "-t", "3", cname], stdout=subprocess.DEVNULL)
    try: coll.wait(timeout=10)
    except subprocess.TimeoutExpired: coll.kill()
    subprocess.run(["docker", "rm", "-f", cname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if mitm.poll() is None:
        mitm.terminate()
        try: mitm.wait(timeout=5)
        except subprocess.TimeoutExpired: mitm.kill()
    m.update(status="interrupted" if stopping["interrupted"] else "finished", ended_ns=now(),
             root_returncode=rc, degraded=bool(lost))
    write_manifest(d, m); rec.event("run_finished", degraded=bool(lost))

def sweep(a):
    for mp in glob.glob(f"{a.runs_root}/*/manifest.json"):
        d = os.path.dirname(mp); m = json.load(open(mp))
        if m.get("status") != "running": continue
        if os.path.exists(f"/proc/{m['supervisor_pid']}"): continue
        run_id = m["run_id"]; rec = Rec(d)
        ids = subprocess.run(["docker", "ps", "-aq", "--filter", f"label=tracewatch.run={run_id}"],
                             capture_output=True, text=True).stdout.split()
        for i in ids: subprocess.run(["docker", "rm", "-f", i], stdout=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", f"confdir={d}/ca"])
        m.update(status="aborted", swept_ns=now()); write_manifest(d, m)
        rec.event("swept", removed_containers=len(ids), note="supervisor died without finalizing")
        print(f"swept {run_id}: removed {len(ids)} container(s)")

if __name__ == "__main__":
    p = argparse.ArgumentParser(); sp = p.add_subparsers(dest="c", required=True)
    r = sp.add_parser("run"); r.add_argument("--run-dir", required=True); r.add_argument("--port", type=int, required=True)
    r.add_argument("--upstream-ca", required=True); r.add_argument("--addon", default=os.path.join(HERE, "p0_3_addon.py")); r.add_argument("cmd", nargs=argparse.REMAINDER)
    s = sp.add_parser("sweep"); s.add_argument("--runs-root", required=True)
    a = p.parse_args()
    if a.c == "run":
        a.cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd; run(a)
    else: sweep(a)

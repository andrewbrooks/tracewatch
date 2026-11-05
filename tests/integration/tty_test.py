"""Interactive (pseudo-terminal) behavior of `tracewatch record`: the target must see a real tty, input must reach
it, and Ctrl-C must reach the TARGET exactly once without killing the recorder's own components.
usage: tty_test.py   (needs Docker + the Tracee image; ~1 min)"""

import http.server
import json
import os
import pty
import select
import shutil
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
TW = str(HERE / ".venv/bin/tracewatch")
OUT = HERE / "out" / "tty"
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def run_in_pty(argv, steps, timeout=150):
    """Run argv on a pty. steps = [(substring to wait for, bytes to send)]. -> (exit code, output text)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(argv[0], argv)
    buf, end = b"", time.time() + timeout
    pending = list(steps)
    status = None
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            buf += chunk
        while pending and pending[0][0].encode() in buf:
            os.write(fd, pending.pop(0)[1])
            time.sleep(0.2)
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            r, _, _ = select.select([fd], [], [], 0.3)
            if r:
                try:
                    buf += os.read(fd, 65536)
                except OSError:
                    pass
            break
    if status is None:
        os.kill(pid, 9)
        _, status = os.waitpid(pid, 0)
        buf += b"\n[test harness: timed out]"
    return os.waitstatus_to_exitcode(status), buf.decode(errors="replace")


def manifest(name):
    return json.loads((OUT / "runs" / name / "manifest.json").read_text())


def events(name):
    return [json.loads(x) for x in (OUT / "runs" / name / "events.jsonl").read_text().splitlines()]


shutil.rmtree(OUT, ignore_errors=True)
(OUT / "runs").mkdir(parents=True)

# ---- A: the target sees a real tty and receives typed input
code, out = run_in_pty(
    [
        TW,
        "record",
        "--out",
        str(OUT / "runs"),
        "--name",
        "tty_a",
        "--",
        "sh",
        "-c",
        'if [ -t 0 ] && [ -t 1 ]; then echo ISATTY; else echo NOTTY; fi; printf "PROMPT> "; read x; echo "got:$x"',
    ],
    [("PROMPT> ", b"hello\n")],
)
check("A: the target's stdin and stdout are a tty", "ISATTY" in out and "NOTTY" not in out)
check("A: typed input reaches the target", "got:hello" in out)
m = manifest("tty_a")
check("A: run finished normally, not degraded", code == 0 and m["status"] == "finished" and not m["degraded"])

# ---- B: Ctrl-C reaches the target exactly once and does not break the recorder's components
flag = OUT / "sigint_count"
script = (
    f"trap 'echo INT >> {flag}; exit 130' INT; echo READY; i=0; while [ $i -lt 120 ]; do sleep 0.5; i=$((i+1)); done"
)
code, out = run_in_pty(
    [TW, "record", "--out", str(OUT / "runs"), "--name", "tty_b", "--", "sh", "-c", script],
    [("READY", b"\x03")],
)
m = manifest("tty_b")
ev = events("tty_b")
check(
    f"B: the target received SIGINT exactly once ({flag.read_text().split() if flag.exists() else 'never'})",
    flag.exists() and flag.read_text().split() == ["INT"],
)
check(f"B: the recorder's components SURVIVED the Ctrl-C (lost={m['lost_components']})", m["lost_components"] == [])
check("B: run is not degraded and was finalized as interrupted", not m["degraded"] and m["status"] == "interrupted")
check("B: the recorder noticed the signal", any(e["kind"] == "signal_received" for e in ev))
check(f"B: the target's exit status is propagated (got {code}, want 130)", code == 130)


# ---- C: a target that keeps working after Ctrl-C (cleanup, final network calls) must still be recorded
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
port = srv.server_address[1]
flag_c = OUT / "sigint_count_c"
script = (
    f"trap 'echo INT >> {flag_c}; sleep 2; curl -s -o /dev/null http://127.0.0.1:{port}/cleanup-after-sigint; "
    f"sleep 2; curl -s -o /dev/null http://127.0.0.1:{port}/cleanup-2; exit 130' INT; echo READY; "
    "i=0; while [ $i -lt 120 ]; do sleep 0.5; i=$((i+1)); done"
)
code, out = run_in_pty(
    [TW, "record", "--out", str(OUT / "runs"), "--name", "tty_c", "--", "sh", "-c", script],
    [("READY", b"\x03")],
)
m = manifest("tty_c")
ev = events("tty_c")
flows = [json.loads(x) for x in (OUT / "runs" / "tty_c" / "flows.jsonl").read_text().splitlines()]
paths = [f["path"] for f in flows if f["kind"] == "flow"]
check(
    f"C: the target received SIGINT exactly once ({flag_c.read_text().split() if flag_c.exists() else 'never'})",
    flag_c.exists() and flag_c.read_text().split() == ["INT"],
)
check(
    f"C: the proxy SURVIVED the Ctrl-C and recorded the post-signal requests ({paths})",
    "/cleanup-after-sigint" in paths and "/cleanup-2" in paths,
)
check(
    f"C: no component was lost (lost={m['lost_components']}), run not degraded",
    m["lost_components"] == [] and not m["degraded"],
)
check(
    "C: Tracee kept recording the post-signal activity",
    any(
        json.loads(x).get("processName") == "curl"
        for x in (OUT / "runs" / "tty_c" / "tracee.jsonl").read_text().splitlines()
        if x.startswith("{")
    ),
)
check("C: finalized as interrupted, exit status 130 propagated", m["status"] == "interrupted" and code == 130)
check("C: the recorder noticed the signal", any(e["kind"] == "signal_received" for e in ev))
srv.shutdown()
sys.exit(0 if ok else 1)

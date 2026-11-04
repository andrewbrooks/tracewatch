"""Traced workload for spike p0_6. Runs each join edge case as its own subprocess so its pid is the
ground truth, and writes truth.json. usage: workload.py RUN_DIR PROXY_PORT UP_PORT HTTP_PORT"""
import json, os, subprocess, sys, time
d, pp, up, hp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
ca = f"{d}/ca/mitmproxy-ca-cert.pem"; here = os.path.dirname(os.path.abspath(__file__)); truth = {}
def save(): json.dump(truth, open(f"{d}/truth.json", "w"))
def run(name, argv, wait=True):
    p = subprocess.Popen(argv); truth[name] = {"pid": p.pid, "t_start_ns": time.time_ns(), "t_start_mono_ns": time.monotonic_ns()}; save()
    if wait: truth[name]["rc"] = p.wait(); truth[name]["t_end_ns"] = time.time_ns(); save()
    return p
HTTPREQ = lambda path: f"GET http://127.0.0.1:{hp}{path} HTTP/1.1\\r\\nHost: 127.0.0.1:{hp}\\r\\nConnection: close\\r\\n\\r\\n"
# 1. forced source-port reuse: three different processes, same local port 41000, sequential
for i in (1, 2, 3):
    run(f"reuse{i}", [sys.executable, f"{here}/p0_6_reuse_client.py", str(pp), ca, str(up), "41000", f"/reuse{i}"]); time.sleep(1.5)
# 2. shared socket: bash opens the proxy connection, a background child inherits fd 3 and outlives it
run("shared", ["bash", "-c", f'exec 3<>/dev/tcp/127.0.0.1/{pp}; sleep 3 & printf "{HTTPREQ("/shared")}" >&3; cat <&3 >/dev/null'])
# 3. keep-alive (HTTP/1.1) and HTTP/2: two requests on one connection
run("ka", ["curl", "-s", "-o", "/dev/null", f"https://localhost:{up}/ka1", "-o", "/dev/null", f"https://localhost:{up}/ka2"])
run("h2req", ["curl", "-s", "--http2", "-o", "/dev/null", f"https://localhost:{up}/h2a", "-o", "/dev/null", f"https://localhost:{up}/h2b"])
# 4. fire-and-forget: send the request and exit at once (client may be gone before the proxy looks)
ff = lambda n: ["bash", "-c", f'exec 3<>/dev/tcp/127.0.0.1/{pp}; printf "{HTTPREQ("/ff" + n)}" >&3']
run("ff1", ff("1")); time.sleep(1.5)
a = run("ff2", ff("2"), wait=False); b = run("ff3", ff("3"), wait=False); a.wait(); b.wait(); time.sleep(1)

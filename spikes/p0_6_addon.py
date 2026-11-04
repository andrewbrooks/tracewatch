"""mitmproxy addon (spike p0_6): record, at client-connect time, which pid(s) hold the client's
socket, keyed by mitmproxy's unique connection id (NOT by client port, which can be reused)."""
import glob, json, os, time
from mitmproxy import http

OUT = os.environ["TW_FLOWS"]

def w(rec):
    rec["t_wall_ns"] = time.time_ns()
    rec["t_mono_ns"] = time.monotonic_ns()      # CLOCK_MONOTONIC: immune to the wall-clock steps seen on this host
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")

def _inode(sport, pport):
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try: rows = open(fn).read().splitlines()[1:]
        except OSError: continue
        for r in rows:
            p = r.split()
            if int(p[1].rsplit(":", 1)[1], 16) == sport and int(p[2].rsplit(":", 1)[1], 16) == pport and p[9] != "0":
                return p[9]
    return None

def _holders(inode):
    want, pids, n = f"socket:[{inode}]", set(), 0
    for d in glob.glob("/proc/[0-9]*/fd"):
        n += 1
        try:
            for fd in os.listdir(d):
                if os.readlink(f"{d}/{fd}") == want: pids.add(int(d.split("/")[2]))
        except OSError: continue
    return sorted(pids), n

def client_connected(client):
    t0 = time.perf_counter(); sport, pport = client.peername[1], client.sockname[1]
    inode = None
    for _ in range(4):                       # row may lag accept by ~ms; cap the wait, this blocks the proxy loop
        inode = _inode(sport, pport)
        if inode: break
        time.sleep(0.002)
    holders, nproc = _holders(inode) if inode else ([], 0)
    acc = int(client.timestamp_start * 1e9)
    lag = time.time_ns() - acc
    w({"kind": "conn", "conn_id": client.id, "accept_ns": acc, "hook_lag_ms": round(lag / 1e6, 1), "accept_mono_ns": time.monotonic_ns() - lag, "client_port": sport, "proxy_port": pport, "inode": inode,
       "holder_pids": holders, "lookup_ms": round((time.perf_counter() - t0) * 1000, 2), "procs_scanned": nproc})

def request(flow: http.HTTPFlow):
    """Record the request as soon as it arrives, so a flow with no response (client or server gone) is still on disk."""
    w({"kind": "flow", "flow_id": flow.id, "conn_id": flow.client_conn.id, "client_port": flow.client_conn.peername[1],
       "http_version": flow.request.http_version, "scheme": flow.request.scheme,
       "host": flow.request.pretty_host, "path": flow.request.path, "method": flow.request.method})

def response(flow: http.HTTPFlow):
    w({"kind": "flow_result", "flow_id": flow.id, "status": flow.response.status_code})

def error(flow: http.HTTPFlow):
    w({"kind": "flow_result", "flow_id": flow.id, "error": str(flow.error)})

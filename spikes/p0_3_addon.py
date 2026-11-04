"""mitmproxy addon for spike p0_3: at client-connect time, resolve the client's source port to the
pid(s) holding that socket (via /proc/net/tcp inode + /proc/*/fd) and record it. Capture-time data
only; the join to Tracee happens afterwards."""
import glob, json, os, time
from mitmproxy import http

OUT = os.environ["TW_FLOWS"]

def w(rec):
    rec["t_wall_ns"] = time.time_ns()
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")

def _inode(sport, pport):
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = open(fn).read().splitlines()[1:]
        except OSError:
            continue
        for r in rows:
            p = r.split()
            if int(p[1].rsplit(":", 1)[1], 16) == sport and int(p[2].rsplit(":", 1)[1], 16) == pport:
                return p[9]
    return None

def _holders(inode):
    want, pids = f"socket:[{inode}]", set()
    for d in glob.glob("/proc/[0-9]*/fd"):
        try:
            for fd in os.listdir(d):
                if os.readlink(f"{d}/{fd}") == want:
                    pids.add(int(d.split("/")[2]))
        except OSError:
            continue
    return sorted(pids)

def client_connected(client):
    sport, pport = client.peername[1], client.sockname[1]
    inode = None
    for _ in range(20):                      # socket row may lag a few ms behind accept
        inode = _inode(sport, pport)
        if inode:
            break
        time.sleep(0.005)
    w({"kind": "conn", "client_port": sport, "proxy_port": pport, "inode": inode,
       "holder_pids": _holders(inode) if inode else []})

def response(flow: http.HTTPFlow):
    w({"kind": "flow", "client_port": flow.client_conn.peername[1], "scheme": flow.request.scheme,
       "host": flow.request.pretty_host, "path": flow.request.path, "status": flow.response.status_code})

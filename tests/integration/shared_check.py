"""Checks for shared_socket.sh.  usage: shared_check.py RUN_DIR RESULTS.json"""

import json
import os
import sys
from pathlib import Path

from tracewatch.join import load
from tracewatch.model import build

run, resf = sys.argv[1], sys.argv[2]
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


if not os.path.exists(resf):
    print("FAIL the client did not finish")
    sys.exit(1)
res = json.load(open(resf))
check("all four scenarios got an HTTP 200 through the proxy", all("200" in v for v in res.values()) and len(res) == 4)

fl = load(f"{run}/flows.jsonl")
tr = load(f"{run}/tracee.jsonl")
model = build(Path(run))

# identify processes by argv: the parent is the client script, children carry their mode/label
procs = {}
for p in model["processes"]:
    c = p["cmdline"]
    if "--child" in c:
        procs["child:" + c.split("--child")[1].split()[1]] = p["pid"]
    elif "shared_client.py" in c:
        procs["parent"] = p["pid"]
check("the parent and all four children are in the process tree", len(procs) == 5)

net = {}
for h in model["http"]:
    net[h["path"].lstrip("/")] = h
conns = {c["conn_id"]: c for c in fl if c["kind"] == "conn"}
flows = {f["path"].lstrip("/"): f for f in fl if f["kind"] == "flow"}
check("each scenario produced a recorded flow", set(flows) >= {"s1", "s2", "s3", "s4"})
want = {  # scenario -> (who the recording should name, why)
    "s2": ("parent", "two holders at accept; only the parent has the connect event"),
    "s3": ("child:s3", "the parent closed its copy: one holder, the connector"),
    "s4": ("child:s4", "two holders at accept; only the child has the connect event"),
    # KNOWN LIMIT: the recording says who OPENED the connection (the holder at accept time). Nothing in the captured
    # events shows which process later wrote to a socket it inherited, so a child sending on its parent's
    # connection is attributed to the parent. This asserts the limit stays what the documentation says it is.
    "s1": ("parent", "KNOWN LIMIT: attributed to the opener, although a child wrote the request"),
}
for label, (who, why) in want.items():
    h, c = net[label], conns[flows[label]["conn_id"]]
    a = h["attribution"]
    check(f"{label}: attributed to {who} ({why}) [{a['method']}]", a["pid"] == procs[who])
    check(
        f"{label}: the named pid is one of the recorded holders and in the tree",
        a["pid"] in c["holder_pids"] and a["pid"] in a["candidates"],
    )
check("no scenario was left unattributed or called outside the tree", all(net[k]["attribution"]["pid"] for k in want))
sys.exit(0 if ok else 1)

"""Checks for websocket.sh.  usage: ws_check.py RUN_DIR RESULTS.json FLAGS"""

import hashlib
import json
import os
import sys

from tracewatch.join import join_run, load

run, resf, flags = sys.argv[1], sys.argv[2], sys.argv[3]
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


if not os.path.exists(resf):
    print("FAIL the client did not finish (no results): websockets through the proxy are broken")
    sys.exit(1)
res = json.load(open(resf))
fl = load(f"{run}/flows.jsonl")
man = json.load(open(f"{run}/manifest.json"))

# ---- the traffic itself must be correct and prompt, recorded or not
check("handshake worked and the server's hello arrived", res["hello"]["hello"] == "VISMARKws")
check("3 echoes round-tripped in order", [e["n"] for e in res["echoes"]] == [0, 1, 2])
want = hashlib.sha256("".join(f"burst-{i:04d}" for i in range(200)).encode()).hexdigest()
check(
    "200-message burst arrived complete and in order (sha256)",
    res["burst"]["count"] == 200 and res["burst"]["sha256"] == want,
)
check("1 KB binary message echoed intact", res["binary"]["echoed_intact"])
check(
    "200 KB text message arrived intact",
    res["big"]["len"] == 200_000
    and res["big"]["sha256"] == hashlib.sha256(("0123456789" * 20000)[:200_000].encode()).hexdigest(),
)
sl = res["slow"]
check(
    f"slow stream is NOT buffered: first at {sl[0]} s, spread {sl[-1] - sl[0]:.2f} s (want first<0.6, spread>=1.2)",
    len(sl) == 6 and sl[0] < 0.6 and sl[-1] - sl[0] >= 1.2,
)
check("client-initiated close completed with code 1000", res["conn1_close"]["code"] == 1000)
check("server-initiated close seen by the client (4001)", res["conn2_close"]["code"] == 4001)
print(
    f"INFO the client saw the abrupt upstream drop as: {res['conn3_close']} (mitmproxy turns it into an orderly close)"
)

# ---- the recording
opens = [r for r in fl if r["kind"] == "ws_open"]
msgs = [r for r in fl if r["kind"] == "ws_message"]
closes = [r for r in fl if r["kind"] == "ws_close"]
check("3 websocket connections recorded (open)", len(opens) == 3)
check("3 websocket connections recorded (close)", len(closes) == 3)
check("messages were recorded", len(msgs) > 100)
by_flow = {}
for r in msgs:
    by_flow.setdefault(r["flow_id"], []).append(r)
chat = max(by_flow.values(), key=len)
seqs = [r["seq"] for r in chat]
check("messages are numbered in order, no duplicates", seqs == sorted(seqs) and len(set(seqs)) == len(seqs))
dirs = {r["dir"] for r in chat}
check("both directions recorded", dirs == {"c2s", "s2c"})
txt = [r for r in chat if r["body"].get("captured")]
check(
    "text messages captured with their markers",
    any("VISMARKwsmsg" in r["body"]["text"] for r in txt) and any("VISMARKwsreply" in r["body"]["text"] for r in txt),
)
limited = "--ws-max-records" in flags  # with a tiny record limit these messages come after it and are only counted
if not limited:
    check(
        "binary message described, not stored",
        any(
            r["opcode"] == "binary"
            and r["body"]["captured"] is False
            and r["body"]["reason"] == "binary"
            and r["body"]["size"] == 1024
            for r in chat
        ),
    )
    big = [r for r in chat if r["body"]["size"] == 200_000]
    check(
        "200 KB message: size recorded, stored text truncated",
        bool(big) and (big[0]["body"].get("truncated") or not big[0]["body"]["captured"]),
    )
cl = {c["flow_id"]: c for c in closes}
codes = sorted(c["close_code"] for c in closes if c.get("close_code") is not None)
check(f"close codes recorded ({codes}): 1000, 4001", 1000 in codes and 4001 in codes)
check(
    "the abrupt connection is recorded as 1006 (abnormal closure), clean=false: the ground truth the client never sees",
    any(c.get("close_code") == 1006 and c.get("clean") is False for c in closes)
    and sum(c["clean"] for c in closes) == 2,
)
check(
    "close totals add up for the busy connection",
    any(c["messages"]["c2s"] + c["messages"]["s2c"] >= 200 for c in closes),
)

# ---- no secrets anywhere in the run dir
canaries = [
    "CANARYwsbearer0123456789",
    "CANARYwsquery0123456789",
    "CANARYwspw0123456789",
    "CANARYwstoken0123456789",
    "CANARYclosetoken0123456789",
]
leaks = []
for base, _, files in os.walk(run):
    for f in files:
        data = open(os.path.join(base, f), "rb").read()
        for c in canaries:
            if c.encode() in data:
                leaks.append((f, c))
for lk in leaks:
    print("  LEAK:", lk)
check("NO planted websocket secret anywhere in the run directory", not leaks)
check("handshake marker survived (not over-redacted)", "VISMARKwshdr" in open(f"{run}/flows.jsonl").read())

# ---- attribution: the upgrade request is a normal flow, so the join covers every websocket
rows, _, _ = join_run(run, man["proxy_port"])
ups = [r for r in rows if r["path"].startswith("/chat") or r["path"].startswith("/abrupt")]
check(
    "all 3 websocket upgrades are attributed in-tree to one client pid",
    len(ups) == 3 and all(r["scope"] == "in-tree" for r in ups) and len({r["pid"] for r in ups}) == 1,
)
if "--ws-max-records" in flags:
    over = [c for c in closes if c.get("suppressed", {}).get("records", 0) > 0]
    check(
        "per-connection record limit: excess messages suppressed but counted in the close summary",
        bool(over)
        and over[0]["messages"]["c2s"] + over[0]["messages"]["s2c"]
        > len([r for r in by_flow.get(over[0]["flow_id"], [])]),
    )
    budget = [r for r in chat if r["body"].get("reason") == "websocket connection budget"]
    check(
        "per-connection body budget: later messages keep metadata, bodies are disabled with a stated reason",
        bool(budget),
    )
sys.exit(0 if ok else 1)

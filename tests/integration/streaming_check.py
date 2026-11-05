"""Checks for streaming.sh.  usage: streaming_check.py RUN_DIR RESULTS.json"""

import json
import sys

from tracewatch.join import load

run, resf = sys.argv[1], sys.argv[2]
res = json.load(open(resf))
fl = load(f"{run}/flows.jsonl")
flows = {r["flow_id"]: r for r in fl if r["kind"] == "flow"}
results = {r["flow_id"]: r for r in fl if r["kind"] == "flow_result"}
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def rec(path):
    for fid, f in flows.items():
        if f.get("path") == path:
            return f, results.get(fid)
    return None, None


# --- SSE must stream through, not arrive all at once at the end
ev = res["sse"]["events"]
check(
    "SSE: all 6 events delivered intact",
    len(ev) == 6 and [json.loads(e["data"][5:])["n"] for e in ev] == list(range(6)),
)
check(f"SSE: first event arrives promptly (<1.0 s; saw {ev[0]['t'] if ev else None})", bool(ev) and ev[0]["t"] < 1.0)
check(
    f"SSE: events are spread over time, not buffered to the end (span {ev[-1]['t'] - ev[0]['t']:.2f} s, want >=2)",
    len(ev) == 6 and ev[-1]["t"] - ev[0]["t"] >= 2.0,
)
# --- ndjson also streams
nd = res["nd"]["lines"]
check(
    f"ndjson: lines spread over time (span {nd[-1]['t'] - nd[0]['t']:.2f} s, want >=0.6)",
    len(nd) == 4 and nd[-1]["t"] - nd[0]["t"] >= 0.6,
)
# --- integrity of large bodies in both directions
check(
    "big response (3 MB): delivered intact",
    res["big"]["len"] == 3 * 1024 * 1024 and res["big"]["sha256"] == res["big"]["server_sha256"],
)
check(
    "2 MB upload: arrived intact at the server",
    res["upload"]["sent_sha256"] == res["upload"]["server_sha256"] and res["upload"]["server_len"] == 2 * 1024 * 1024,
)
# --- what was captured
f, r = rec("/sse")
b = (r or {}).get("body", {})
check(
    "SSE: body captured (redacted) with its marker, token gone, size recorded",
    b.get("captured") and "VISMARKsse" in b["text"] and "CANARYssetoken" not in b["text"] and b["size"] > 300,
)
f, r = rec("/nd")
b = (r or {}).get("body", {})
check(
    "ndjson: captured with marker, password redacted",
    b.get("captured") and "VISMARKnd" in b["text"] and "CANARYndpw" not in b["text"],
)
f, r = rec("/gz")
b = (r or {}).get("body", {})
check(
    "gzip response: decoded text captured, secret redacted",
    b.get("captured") and "VISMARKgzip" in b["text"] and "CANARYgzpw" not in b["text"],
)
f, r = rec("/big")
b = (r or {}).get("body", {})
check(
    "3 MB response: not stored, but size and reason recorded",
    b.get("captured") is False and b.get("size", 0) >= 3 * 1024 * 1024 and "too large" in b.get("reason", ""),
)
f, r = rec("/upload")
b = (f or {}).get("body", {})
check(
    "2 MB request: not stored, size recorded (not mislabeled 'empty')",
    b.get("captured") is False and b.get("reason") != "empty" and b.get("size", 0) >= 2 * 1024 * 1024,
)
check("no flow without a result record", all(fid in results for fid in flows))
check("no redaction_failed records", not [x for x in fl if x["kind"] == "redaction_failed"])
sys.exit(0 if ok else 1)

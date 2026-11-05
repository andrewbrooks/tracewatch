"""Checks for long_run.sh.  usage: long_check.py RUN_DIR RESULT"""

import os
import sys
from pathlib import Path

from tracewatch.integrity import assess
from tracewatch.join import join_records, load
from tracewatch.model import build

run, resf = sys.argv[1], sys.argv[2]
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


if not os.path.exists(resf):
    print("FAIL the workload did not finish")
    sys.exit(1)
good, sent, secs = map(int, open(resf).read().split())
check(f"the run lasted {secs} s (> 90) and every request succeeded ({good}/{sent})", secs > 90 and good == sent)

m = build(Path(run))
v = assess(Path(run))
check(f"verdict is COMPLETE after a long run ({v['verdict']}: {v['reasons']})", v["verdict"] == "complete")
check("no gaps and no data marked untrusted", not v["gaps"] and not v.get("untrusted_after_mono"))
https = [h for h in m["http"] if h["path"].lstrip("/")[:1] in "ac"]
check(f"every request was recorded exactly once ({len(https)} of {sent})", len(https) == sent)
check(
    "every request is attributed to a process in the tree",
    all(h["attribution"]["pid"] and h["attribution"]["method"].startswith("socket-holder") for h in https),
)
ts = sorted(h["t"] / 1e9 for h in https)
check(f"the recording covers the whole run (first {ts[0]:.1f}s, last {ts[-1]:.1f}s)", ts[0] < 5 and ts[-1] > 90)
gap = max(b - a for a, b in zip(ts, ts[1:], strict=False))
check(f"the 30 s idle gap is a gap in traffic, not a hole in the recording ({gap:.1f}s)", 28 < gap < 40)

# clock stability: calibrate the monotonic offset on the early half and the late half separately
fl, tr = load(f"{run}/flows.jsonl"), [e for e in load(f"{run}/tracee.jsonl") if "eventName" in e]
port = next(c["proxy_port"] for c in fl if c["kind"] == "conn")
mid = sorted(c["accept_mono_ns"] for c in fl if c["kind"] == "conn")
cut = mid[len(mid) // 2]
offs = []
for half in (lambda c: c["accept_mono_ns"] < cut, lambda c: c["accept_mono_ns"] >= cut):
    keep = {c["conn_id"] for c in fl if c["kind"] == "conn" and half(c)}
    sub = [r for r in fl if r.get("conn_id") in keep]
    info = {}
    join_records(sub, [e for e in tr if e["processName"] != "twprobe"], port, info)
    offs.append(info["offset_ns"])
drift_ms = abs(offs[0] - offs[1]) / 1e6
check(f"the clock offset is the same early and late ({drift_ms:.2f} ms drift over ~100 s; want < 25)", drift_ms < 25)
sys.exit(0 if ok else 1)

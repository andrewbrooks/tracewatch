"""Checks for caps.sh.  usage: caps_check.py RUN_DIR OK_COUNT_FILE"""

import json
import os
import sys

from tracewatch.join import join_run

run, okf = sys.argv[1], sys.argv[2]
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def jl(name):
    out, bad = [], 0
    for line in open(f"{run}/{name}", "rb").read().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            bad += 1
    return out, bad


man = json.load(open(f"{run}/manifest.json"))
lim = man["limits"]
fl, fbad = jl("flows.jsonl")
tr, tbad = jl("tracee.jsonl")
ev, _ = jl("events.jsonl")
fsize, tsize = os.path.getsize(f"{run}/flows.jsonl"), os.path.getsize(f"{run}/tracee.jsonl")
print(
    f"flows.jsonl {fsize} B (hard {lim['max_flows_bytes']}, soft {lim['soft_flows_bytes']}), "
    f"tracee.jsonl {tsize} B (cap {lim['max_tracee_bytes']}), caps_hit={man['caps_hit']}"
)

check("the target was unaffected: all 60 requests succeeded", open(okf).read().strip() == "60")
check(
    "run finished normally and is NOT marked degraded (a cap is a limit, not a component failure)",
    man["status"] == "finished" and not man["degraded"] and man["root_returncode"] == 0,
)
check(
    "manifest records the limits and which caps were hit",
    lim["max_flows_bytes"] == 65536 and set(man["caps_hit"]) == {"proxy:soft", "proxy:hard", "tracee:hard"},
)
check("flows.jsonl never exceeds its hard cap, every line valid JSON", fsize <= lim["max_flows_bytes"] and fbad == 0)
check("tracee.jsonl never exceeds its cap, every line valid JSON", tsize <= lim["max_tracee_bytes"] and tbad == 0)
# --- soft cap: bodies first, then nothing
soft = [i for i, r in enumerate(fl) if r["kind"] == "cap_reached" and r["level"] == "soft"]
hard = [i for i, r in enumerate(fl) if r["kind"] == "cap_reached" and r["level"] == "hard"]
check(
    "exactly one soft marker and one hard marker in flows.jsonl",
    len(soft) == 1 and len(hard) == 1 and soft[0] < hard[0],
)
before = [r for r in fl[: soft[0]] if r["kind"] == "flow_result" and "body" in r]
check(
    "before the soft cap, bodies were captured (with markers)",
    any(r["body"].get("captured") and "VISMARKresp" in r["body"]["text"] for r in before),
)
between = [r for r in fl[soft[0] : hard[0]] if r["kind"] in ("flow", "flow_result") and "body" in r]
check(
    "between the caps, records continue but bodies are disabled with a stated reason",
    len(between) > 0
    and all(r["body"]["captured"] is False and r["body"]["reason"] == "size cap: bodies disabled" for r in between),
)
after = [r for r in fl[hard[0] + 1 :] if r["kind"] not in ("redaction_summary", "cap_summary")]
check("after the hard cap nothing but the final summaries is written", not after)
cs = [r for r in fl if r["kind"] == "cap_summary"]
check(
    "the proxy's cap_summary reports drops, and the manifest carries it",
    len(cs) == 1
    and cs[0]["hard_hit"]
    and cs[0]["dropped"].get("flow", 0) > 0
    and man["caps"]["proxy"]["dropped"] == cs[0]["dropped"],
)
# --- tracee cap
tm = [r for r in tr if r.get("kind") == "cap_reached"]
check(
    "exactly one tracee cap marker; manifest counts the dropped lines",
    len(tm) == 1 and man["caps"]["tracee"]["capped"] and man["caps"]["tracee"]["lines_dropped"] > 0,
)
# --- the cap is visible in the recorder's own log, and the recorder kept supervising afterwards
capev = [e["cap"] for e in ev if e["kind"] == "cap_reached"]
check("events.jsonl records each cap exactly once", sorted(capev) == ["proxy:hard", "proxy:soft", "tracee:hard"])
first_cap = min(i for i, e in enumerate(ev) if e["kind"] == "cap_reached")
check("heartbeats continue after the caps were hit", any(e["kind"] == "heartbeat" for e in ev[first_cap:]))
hb = [e for e in ev if e["kind"] == "heartbeat" and "tracee_dropped" in e]
check("heartbeats expose the Tracee drop counter growing", bool(hb) and hb[-1]["tracee_dropped"] > 0)
# --- joining capped data must not claim 'outside-tree'
rows, _, _ = join_run(run, man["proxy_port"])
check(
    f"join over capped data never says 'outside-tree' ({sorted({r['scope'] for r in rows})})",
    rows and "outside-tree" not in {r["scope"] for r in rows},
)
sys.exit(0 if ok else 1)

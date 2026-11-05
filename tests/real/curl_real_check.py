"""Checks for tests/real/curl_real.sh.  usage: curl_real_check.py OUT_DIR"""

import hashlib
import json
import os
import sys

from tracewatch.integrity import assess
from tracewatch.join import join_run, load

out = sys.argv[1]
have = json.load(open(f"{out}/have.json"))
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


def skip(name, why):
    print(f"SKIP {name}: {why}")


def meta(n):
    p = f"{out}/results/{n}.meta"
    return json.load(open(p)) if os.path.exists(p) and os.path.getsize(p) else None


def rc(n):
    p = f"{out}/results/{n}.rc"
    return int(open(p).read()) if os.path.exists(p) else None


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


A, B = f"{out}/runs/A", f"{out}/runs/B"
man = json.load(open(f"{A}/manifest.json"))
fl = load(f"{A}/flows.jsonl")
tr = [e for e in load(f"{A}/tracee.jsonl") if "eventName" in e and e["processName"] != "twprobe"]
flows = [r for r in fl if r["kind"] == "flow"]
results = {r["flow_id"]: r for r in fl if r["kind"] == "flow_result"}
by_path = {}
for f in flows:
    by_path.setdefault((f["host"], f["path"]), []).append(f)


def res(host, path):
    f = by_path.get((host, path), [None])[0]
    return (f, results.get(f["flow_id"])) if f else (None, None)


print(f"services available: {have}")
# ---- the traffic itself behaves like a direct run
check(
    "example.com over HTTP/2 through the proxy (client negotiated h2)",
    meta("example") and meta("example")["http_version"] == "2",
)
check("--http1.1 is honored (client negotiated 1.1)", meta("http1") and meta("http1")["http_version"] == "1.1")
check("plain http:// works through the proxy", meta("plainhttp") and meta("plainhttp")["http_code"] == 200)
check(
    "an unresolvable host surfaces as a failure (curl exit 56: the proxy's 502 on CONNECT; direct would be 6)",
    rc("nohost") == 56,
)
if have["httpbin"]:
    for n in ("gzip", "deflate", "brotli"):
        check(
            f"--compressed {n} body decoded correctly by the client",
            meta(n)["http_code"] == 200 and json.loads(open(f"{out}/results/{n}.body").read()),
        )
    check(
        "redirect chain followed (3 requests)",
        meta("redirect")["http_code"] == 200 and meta("redirect")["num_redirects"] == 2,
    )
    check("20 parallel requests all succeeded", rc("parallel") == 0)
    d, p = json.load(open(f"{out}/direct/drip.meta")), meta("drip")
    extra_ttfb, extra_total = p["time_starttransfer"] - d["time_starttransfer"], p["time_total"] - d["time_total"]
    check(
        f"streaming not buffered: first byte {extra_ttfb:+.2f} s, total {extra_total:+.2f} s vs direct (max 0.5)",
        extra_ttfb < 0.5 and extra_total < 0.5,
    )
else:
    skip("httpbin checks", "httpbin.org unavailable")
if have["ovh"]:
    check(
        "10 MB download byte-identical to the direct download (sha256)",
        sha(f"{out}/results/big.body") == sha(f"{out}/direct/big.bin"),
    )
else:
    skip("10 MB integrity", "proof.ovh.net unavailable")
if have["badssl"]:
    for n in ("expired", "selfsigned"):
        check(
            f"{n}.badssl.com: the proxy refused the bad upstream certificate (client got 502, not the page)",
            meta(n) and meta(n)["http_code"] == 502,
        )

# ---- the recording
check("run A verify: COMPLETE (a real run through real servers loses nothing)", assess(A)["verdict"] == "complete")
check("both HTTP/2 and HTTP/1.1 flows were recorded", {"HTTP/2.0", "HTTP/1.1"} <= {f["http_version"] for f in flows})
f, r = res("example.com", "/")
check("example.com body captured as text", r and r["body"].get("captured") and "<html" in r["body"]["text"].lower())
if have["httpbin"]:
    for path in ("/gzip", "/deflate", "/brotli"):
        f, r = res("httpbin.org", path)
        check(
            f"{path}: wire body decoded and captured ({r['body'].get('reason') or 'ok'})",
            r and r["body"].get("captured") and '"headers"' in r["body"]["text"],
        )
    redir = [x for x in flows if x["host"] == "httpbin.org" and ("redirect" in x["path"] or x["path"] == "/get")]
    check(
        "redirect chain: 3 flows on ONE connection, status 302/302/200",
        len(redir) == 3
        and len({x["conn_id"] for x in redir}) == 1
        and [results[x["flow_id"]]["status"] for x in redir] == [302, 302, 200],
    )
    par = [x for x in flows if "/anything/par" in x["path"]]
    check(
        "20 parallel HTTP/2 requests recorded, multiplexed on one connection, all 200",
        len(par) == 20
        and len({x["conn_id"] for x in par}) == 1
        and all(results[x["flow_id"]].get("status") == 200 for x in par),
    )
    f, r = res("httpbin.org", "/post")
    body = r["body"]["text"] if r and r["body"].get("captured") else ""
    check(
        "POST: the server's echo of our secrets is redacted in the recorded response",
        "CANARYreal" not in body and "VISMARKreal" in body and "[REDACTED:" in body,
    )
    check(
        "POST: the server really received the secrets (the client got them echoed back)",
        "CANARYrealpw0123456789" in open(f"{out}/results/post.body").read(),
    )
if have["cfbr"]:
    f, r = res("developers.cloudflare.com", "/")
    check(
        "large brotli page decoded and captured (truncated after redaction)",
        r and r["body"].get("captured") and r["body"].get("truncated") and "<html" in r["body"]["text"].lower(),
    )
if have["ovh"]:
    f, r = res("proof.ovh.net", "/files/10Mb.dat")
    check(
        "10 MB body described, not stored, with its exact size",
        r and r["body"]["captured"] is False and r["body"]["size"] == 10485760 and "too large" in r["body"]["reason"],
    )
if have["badssl"]:
    f, r = res("expired.badssl.com", "/")
    check("expired certificate recorded as an upstream error", r and "ertificate" in r.get("error", ""))
nohost = [c for c in fl if c["kind"] == "connect" and c["host"] == "no-such-host.invalid"]
check("the failed CONNECT to an unresolvable host is recorded with its destination", len(nohost) == 1)

# ---- attribution and secrets
rows, _, _ = join_run(A, man["proxy_port"])
curl_pids = {e["processId"] for e in tr if e["eventName"] == "sched_process_exec" and e["processName"] == "curl"}
bad = [x for x in rows if not (x["scope"] == "in-tree" and x["pid"] in curl_pids)]
check(f"every recorded flow/tunnel ({len(rows)}) is attributed in-tree to a curl pid Tracee saw exec", rows and not bad)
leaks = [f for base, _, files in os.walk(A) for f in files if b"CANARYreal" in open(os.path.join(base, f), "rb").read()]
check("NO planted secret anywhere in run A's directory (argv, headers, bodies, echoed responses)", not leaks)
argv_ok = (
    any(
        a["name"] == "argv" and "Authorization: Bearer [REDACTED:" in " ".join(a["value"])
        for e in tr
        for a in e["args"]
    )
    if have["httpbin"]
    else True
)
check("tracee argv shows the curl command with the credential redacted", argv_ok)

# ---- run B: a bypass must be reported
vb = assess(B)
check(
    f"run B verify: COMPLETE-WITH-LOSSES ({vb['verdict']}), listing the connection that bypassed the proxy",
    vb["verdict"] == "complete-with-losses" and len(vb["unproxied"]) == 1 and vb["unproxied"][0]["port"] == 443,
)
fb = [r for r in load(f"{B}/flows.jsonl") if r["kind"] == "flow"]
check(
    "run B: the proxied request (api.github.com) is recorded and example.com is NOT",
    [x["host"] for x in fb] == ["api.github.com"],
)
sys.exit(0 if ok else 1)

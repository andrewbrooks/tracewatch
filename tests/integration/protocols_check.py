"""Checks for protocols.sh.  usage: protocols_check.py RUN_DIR RC_FILE PORT LANIP"""

import sys
from collections import Counter
from pathlib import Path

from tracewatch.model import build

run, rcf, port, lanip = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name)


rc = dict(ln.split() for ln in open(rcf))
m = build(Path(run))
http = [h for h in m["http"] if h["status"] is not None or h["error"]]
by = lambda pre: [h for h in http if h["path"].startswith(pre)]  # noqa: E731
raw = open(f"{run}/flows.jsonl").read()

print("INFO exit codes:", rc)
for name in ("keepalive", "h2seq", "h2par", "gz", "deflate", "br", "zst"):
    check(f"curl {name}: the traffic itself worked through the proxy (exit {rc.get(name)})", rc.get(name) == "0")

for name, pre, n in (("keepalive", "/k", 3), ("h2seq", "/h2", 3), ("h2par", "/m", 6)):
    fl = by(pre)
    conns = {h["conn_id"] for h in fl}
    versions = Counter(h["http_version"] for h in fl)
    pids = {h["attribution"]["pid"] for h in fl}
    check(f"{name}: all {n} requests recorded ({len(fl)})", len(fl) == n)
    check(f"{name}: attributed to ONE process ({sorted(pids, key=str)})", len(pids) == 1 and None not in pids)
    check(f"{name}: every request has a status", all(h["status"] == 200 for h in fl))
    print(f"INFO {name}: {len(conns)} connection(s), protocol {dict(versions)}")
for name, pre in (("h2seq", "/h2"), ("h2par", "/m")):
    fl = by(pre)
    check(
        f"{name}: really HTTP/2 (client to proxy), not a silent downgrade",
        {h["http_version"] for h in fl} == {"HTTP/2.0"},
    )
    check(
        f"{name}: the upstream answered over h2 too (body says so)",
        all('"proto":"h2"' in (h["resp_body"] or {}).get("text", "") for h in fl),
    )
check("h2 sequential: the 3 requests shared one connection", len({h["conn_id"] for h in by("/h2")}) == 1)
check("h2 multiplexed: the 6 requests shared one connection", len({h["conn_id"] for h in by("/m")}) == 1)
check("keep-alive: the 3 requests shared one connection", len({h["conn_id"] for h in by("/k")}) == 1)

for name in ("gz", "deflate", "br"):
    h = by("/" + name)[0]
    body = h["resp_body"]
    check(
        f"{name}: body was decoded and the secret inside it redacted ({body.get('text', '')[:50]!r})",
        "REDACTED" in body.get("text", "") and "TOKENcompressed" not in body.get("text", ""),
    )
z = by("/zst")[0]["resp_body"]
check(f"zstd: body is described, not stored undecoded ({z})", not z.get("text") or "REDACTED" in z.get("text", ""))
check("no compressed or plain copy of the secret anywhere in flows.jsonl", "TOKENcompressed" not in raw)

tun = lambda host_path: [h for h in m["http"] if h["method"] == "CONNECT"]  # noqa: E731
check(
    f"pinned client (checks AFTER the handshake): curl refused the proxy's certificate (exit {rc.get('pin')})",
    rc.get("pin") not in ("0", None),
)
check(
    f"untrusted CA (fails DURING the handshake): curl refused (exit {rc.get('untrusted')})",
    rc.get("untrusted") not in ("0", None),
)
check("neither client had request content recorded", not by("/pin") and not by("/untrusted"))
rows = tun(None)
print("INFO tunnels:", [(h["host"], h["path"], h["error"]) for h in rows])
check(
    "post-handshake pin: a tunnel row says TLS completed and no request followed",
    any("TLS completed, then the client sent no request" in (h["error"] or "") for h in rows),
)
check(
    "handshake-time rejection: a tunnel row says the client refused the certificate",
    any("refused the recorder's certificate" in (h["error"] or "") for h in rows),
)
rej = m["integrity"].get("tls_rejected", [])
check(
    f"handshake-time rejection: integrity lists the host ({rej})",
    any(r["host"] == "localhost" and r["count"] >= 1 for r in rej),
)
check(
    "handshake-time rejection: a finding cites the tunnel event",
    any(f["rule"] == "tls-client-rejected" and f["events"] for f in m["findings"]),
)

un = m["integrity"].get("unproxied", [])
check(
    f"bypass: the direct connection to {lanip}:{port} is flagged ({un})",
    any(u["dst"] == lanip and u["count"] >= 1 for u in un),
)
check("bypass: verdict is not a plain 'complete'", m["integrity"]["verdict"] != "complete")
print("INFO verdict:", m["integrity"]["verdict"], m["integrity"]["reasons"])
sys.exit(0 if ok else 1)

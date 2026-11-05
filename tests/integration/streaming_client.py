"""Traced client for streaming.sh: talks HTTPS through the recorder's proxy (env HTTPS_PROXY + CA) and
records, per scenario, what it received and WHEN. usage: streaming_client.py UPPORT RESULTS.json"""

import gzip
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
from urllib.parse import urlsplit

up, out = int(sys.argv[1]), sys.argv[2]
px = urlsplit(os.environ["HTTPS_PROXY"])
ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])


def conn():
    c = http.client.HTTPSConnection(px.hostname, px.port, context=ctx, timeout=60)
    c.set_tunnel("localhost", up)
    return c


res = {}
# 1. SSE: one event every 0.5 s. Record when each arrives.
c = conn()
t0 = time.monotonic()
c.request("GET", "/sse")
r = c.getresponse()
ev = []
while True:
    line = r.readline()
    if not line:
        break
    if line.startswith(b"data:"):
        ev.append({"t": round(time.monotonic() - t0, 3), "data": line.decode().strip()})
res["sse"] = {"status": r.status, "events": ev, "total_s": round(time.monotonic() - t0, 3)}
c.close()
# 2. big response (3 MB, Content-Length): integrity
c = conn()
c.request("GET", "/big")
r = c.getresponse()
body = r.read()
res["big"] = {
    "status": r.status,
    "len": len(body),
    "sha256": hashlib.sha256(body).hexdigest(),
    "server_sha256": r.getheader("X-Sha256"),
}
c.close()
# 3. gzip response
c = conn()
c.request("GET", "/gz")
r = c.getresponse()
raw = r.read()
res["gz"] = {"status": r.status, "encoding": r.getheader("Content-Encoding"), "text": gzip.decompress(raw).decode()}
c.close()
# 4. ndjson, chunked, 0.3 s apart
c = conn()
t0 = time.monotonic()
c.request("GET", "/nd")
r = c.getresponse()
nd = []
while True:
    line = r.readline()
    if not line:
        break
    nd.append({"t": round(time.monotonic() - t0, 3), "line": line.decode().strip()})
res["nd"] = {"status": r.status, "lines": nd}
c.close()
# 5. 2 MB upload: integrity
payload = bytes((i * 7) & 0xFF for i in range(2 * 1024 * 1024))
c = conn()
c.request("POST", "/upload", body=payload, headers={"Content-Type": "application/octet-stream"})
r = c.getresponse()
echoed = json.loads(r.read())
res["upload"] = {
    "status": r.status,
    "sent_sha256": hashlib.sha256(payload).hexdigest(),
    "server_sha256": echoed["sha256"],
    "server_len": echoed["len"],
}
c.close()
json.dump(res, open(out, "w"))

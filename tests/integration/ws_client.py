"""Traced websocket client for websocket.sh (goes through the recorder's proxy via env).
usage: ws_client.py UPPORT RESULTS.json"""

import hashlib
import json
import os
import ssl
import sys
import time

from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

up, out = int(sys.argv[1]), sys.argv[2]
ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
uri = f"wss://localhost:{up}"
res = {}

# ---- conn 1: the busy one
hdrs = {"Authorization": "Bearer CANARYwsbearer0123456789", "X-Visible": "VISMARKwshdr"}
with connect(f"{uri}/chat?api_key=CANARYwsquery0123456789&room=VISMARKroom", ssl=ctx, additional_headers=hdrs) as ws:
    res["hello"] = json.loads(ws.recv())
    echoes = []
    for n in range(3):
        ws.send(json.dumps({"type": "echo", "n": n, "password": "CANARYwspw0123456789", "note": "VISMARKwsmsg"}))
        echoes.append(json.loads(ws.recv()))
    res["echoes"] = echoes
    ws.send(json.dumps({"type": "burst", "count": 200}))
    got = [ws.recv() for _ in range(200)]
    res["burst"] = {"count": len(got), "sha256": hashlib.sha256("".join(got).encode()).hexdigest()}
    blob = os.urandom(1024)
    ws.send(blob)
    back = ws.recv()
    res["binary"] = {"echoed_intact": back == blob, "len": len(back)}
    ws.send(json.dumps({"type": "big"}))
    big = ws.recv()
    res["big"] = {"len": len(big), "sha256": hashlib.sha256(big.encode()).hexdigest()}
    ws.send(json.dumps({"type": "slow", "count": 6}))
    t0 = time.monotonic()
    res["slow"] = [round(time.monotonic() - t0, 3) for _ in range(6) if ws.recv()]
    ws.close(1000, "bye VISMARKclose token=CANARYclosetoken0123456789")
    res["conn1_close"] = {"code": ws.close_code, "reason": ws.close_reason}

# ---- conn 2: the server closes it
with connect(f"{uri}/chat", ssl=ctx) as ws:
    ws.recv()
    ws.send(json.dumps({"type": "close", "code": 4001, "reason": "server says VISMARKsrvclose"}))
    try:
        ws.recv()
    except ConnectionClosed as e:
        res["conn2_close"] = {"code": e.rcvd.code if e.rcvd else None, "reason": e.rcvd.reason if e.rcvd else None}

# ---- conn 3: the server drops the TCP connection without a close handshake
with connect(f"{uri}/abrupt", ssl=ctx) as ws:
    res["abrupt_hello"] = json.loads(ws.recv())
    try:
        ws.recv()
    except ConnectionClosed as e:
        res["conn3_close"] = {"code": e.rcvd.code if e.rcvd else None, "clean": e.rcvd is not None}
json.dump(res, open(out, "w"))

"""wss test server for websocket.sh.  usage: ws_server.py PORT CERT KEY"""

import json
import socket
import ssl
import sys
import time

from websockets.sync.server import serve

port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
BIG = ("0123456789" * 20000)[:200_000]


def handler(ws):
    ws.send(json.dumps({"hello": "VISMARKws", "access_token": "CANARYwstoken0123456789"}))
    if ws.request.path.startswith("/abrupt"):
        time.sleep(0.2)
        ws.socket.shutdown(socket.SHUT_RDWR)  # no close frame at all
        return
    for msg in ws:
        if isinstance(msg, bytes):
            ws.send(msg)
            continue
        m = json.loads(msg)
        t = m.get("type")
        if t == "echo":
            ws.send(json.dumps({"type": "echo-reply", "n": m["n"], "note": "VISMARKwsreply"}))
        elif t == "burst":
            for i in range(m["count"]):
                ws.send(f"burst-{i:04d}")
        elif t == "big":
            ws.send(BIG)
        elif t == "slow":
            for i in range(m["count"]):
                ws.send(f"slow-{i}")
                time.sleep(0.3)
        elif t == "close":
            ws.close(m["code"], m["reason"])
            return


with serve(handler, "127.0.0.1", port, ssl=ctx, max_size=2**22) as server:
    server.serve_forever()

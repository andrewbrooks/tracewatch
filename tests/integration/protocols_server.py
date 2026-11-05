"""HTTPS (HTTP/1.1 keep-alive) test server for protocols.sh.  usage: protocols_server.py PORT CERT KEY
/gz /deflate /br /zst answer a JSON body carrying a secret, compressed that way; anything else answers plain JSON."""

import gzip
import http.server
import json
import socket
import ssl
import sys
import threading
import time
import zlib

import brotli
import h2.config
import h2.connection
import h2.events

port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
BODY = json.dumps({"access_token": "TOKENcompressed0123456789abcdef", "ok": True}).encode()


def zstd_raw(data: bytes) -> bytes:
    """A valid zstd frame holding one RAW (uncompressed) block: a decoder must support zstd to read it, and no
    compressor is needed to make it."""
    assert len(data) < 256
    return b"\x28\xb5\x2f\xfd" + bytes([0x20, len(data)]) + ((len(data) << 3) | 1).to_bytes(3, "little") + data


ENC = {
    "/gz": ("gzip", gzip.compress(BODY)),
    "/deflate": ("deflate", zlib.compress(BODY)),
    "/br": ("br", brotli.compress(BODY)),
    "/zst": ("zstd", zstd_raw(BODY)),
}


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        enc, body = ENC.get(self.path.split("?")[0], (None, json.dumps({"path": self.path}).encode()))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if enc:
            self.send_header("Content-Encoding", enc)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve_h2(h2port):
    """An HTTP/2-only TLS server (port+1): the recorder can only speak h2 to a client if the upstream does too."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.set_alpn_protocols(["h2"])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", h2port))
    ls.listen(32)

    def conn_loop(raw):
        try:
            sock = ctx.wrap_socket(raw, server_side=True)
            c = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
            c.initiate_connection()
            sock.sendall(c.data_to_send())
            paths = {}
            while data := sock.recv(65536):
                for ev in c.receive_data(data):
                    if isinstance(ev, h2.events.RequestReceived):
                        paths[ev.stream_id] = dict(ev.headers)[b":path"].decode()
                    elif isinstance(ev, h2.events.StreamEnded):
                        time.sleep(0.05)  # keep several streams in flight at once
                        body = json.dumps({"path": paths.pop(ev.stream_id), "proto": "h2"}).encode()
                        c.send_headers(
                            ev.stream_id,
                            [
                                (":status", "200"),
                                ("content-type", "application/json"),
                                ("content-length", str(len(body))),
                            ],
                        )
                        c.send_data(ev.stream_id, body, end_stream=True)
                sock.sendall(c.data_to_send())
        except (OSError, h2.exceptions.ProtocolError):
            pass

    while True:
        raw, _ = ls.accept()
        threading.Thread(target=conn_loop, args=(raw,), daemon=True).start()


threading.Thread(target=serve_h2, args=(port + 1,), daemon=True).start()
srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain(crt, key)
srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()

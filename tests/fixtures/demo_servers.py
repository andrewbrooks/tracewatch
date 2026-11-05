"""Local HTTPS (+ plain HTTP) servers for the demo workload. usage: demo_servers.py HTTPS_PORT HTTP_PORT CERT KEY"""

import http.server
import json
import ssl
import sys
import threading
import time

https_port, http_port, crt, key = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
BLOB = ("TRACEWATCH demo payload line\n" * 2000).encode()


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/download"):
            self._send(200, BLOB, "text/plain")
        elif self.path.startswith("/api/json"):
            self._send(
                200,
                json.dumps({"status": "ok", "access_token": "DEMOsecrettoken0123456789", "items": [1, 2, 3]}).encode(),
            )
        elif self.path.startswith("/slow"):
            time.sleep(1.2)
            self._send(200, b'{"slow":true}')
        elif self.path.startswith("/missing"):
            self._send(404, b'{"error":"not found"}')
        elif self.path.startswith("/basic"):
            self._send(200, b'{"auth":"basic"}')
        else:
            self._send(200, b'{"ok":true}')

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self._send(
            201, b'{"created":true}', extra=[("Set-Cookie", "session=DEMOsessioncookie0123456789; Path=/; HttpOnly")]
        )

    def log_message(self, *a):
        pass


def serve(port, tls):
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), H)
    if tls:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(crt, key)
        srv.socket = c.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


threading.Thread(target=serve, args=(http_port, False), daemon=True).start()
serve(https_port, True)

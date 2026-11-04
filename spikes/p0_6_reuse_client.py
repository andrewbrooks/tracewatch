"""HTTPS GET through a CONNECT proxy from a fixed local port (forces source-port reuse across runs)."""
import socket, ssl, sys
pp, ca, up, lp, path = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try: s.bind(("127.0.0.1", lp)); s.connect(("127.0.0.1", pp))
except OSError as e: print("REUSE_FAIL", e); sys.exit(3)
s.sendall(f"CONNECT localhost:{up} HTTP/1.1\r\nHost: localhost:{up}\r\n\r\n".encode())
buf = b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
t = ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname="localhost")
t.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost:{up}\r\nConnection: close\r\n\r\n".encode())
while t.recv(4096): pass
t.close()

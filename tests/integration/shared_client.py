"""Workload for shared_socket.sh: one TCP connection to the proxy that SEVERAL processes hold.
usage: shared_client.py PORT RESULTS.json      (child mode: shared_client.py --child MODE LABEL FD PORT)

Each scenario sends one plain-HTTP request through the recorder's proxy and the recording is asked who did it.
  s1  parent connects, THEN a child inherits the connected socket and sends the request   (opener != writer)
  s2  child inherits an unconnected socket; the PARENT connects and sends                  (two holders at accept)
  s3  parent hands an unconnected socket to a child and closes its copy; the CHILD connects (one holder: the child)
  s4  both hold an unconnected socket; the CHILD connects and sends                        (two holders at accept)
"""

import json
import os
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

ME = os.path.abspath(__file__)


def proxy_addr():
    u = urlparse(os.environ["HTTP_PROXY"])
    return u.hostname, u.port


def request(sock, label, port):
    sock.sendall(
        f"GET http://127.0.0.1:{port}/{label} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    data = b""
    while chunk := sock.recv(65536):
        data += chunk
    return data.split(b"\r\n", 1)[0].decode(errors="replace")


def child(mode, label, fd, port):
    s = socket.socket(fileno=int(fd))
    if mode == "hold":  # just keep the inherited descriptor alive across the proxy's accept-time lookup
        time.sleep(2.5)
        return
    if mode == "connect":
        s.connect(proxy_addr())
    time.sleep(0.5 if mode == "send" else 0)
    print(request(s, label, port))


def spawn(mode, label, sock, port):
    return subprocess.Popen(
        [sys.executable, ME, "--child", mode, label, str(sock.fileno()), str(port)],
        pass_fds=[sock.fileno()],
        stdout=subprocess.PIPE,
        text=True,
    )


def main():
    port, out = int(sys.argv[1]), sys.argv[2]
    res = {}
    # s1: connected first, inherited later
    s = socket.create_connection(proxy_addr())
    time.sleep(0.4)  # the proxy has looked up the holders by now: only this process held it
    c = spawn("send", "s1", s, port)
    res["s1"] = c.communicate()[0].strip()
    s.close()
    # s2: child holds the unconnected socket, parent connects
    s = socket.socket()
    c = spawn("hold", "s2", s, port)
    time.sleep(0.3)
    s.connect(proxy_addr())
    res["s2"] = request(s, "s2", port)
    s.close()
    c.wait()
    # s3: parent gives the socket away
    s = socket.socket()
    c = spawn("connect", "s3", s, port)
    s.close()
    res["s3"] = c.communicate()[0].strip()
    # s4: both hold, child connects
    s = socket.socket()
    c = spawn("connect", "s4", s, port)
    res["s4"] = c.communicate()[0].strip()
    s.close()
    json.dump(res, open(out, "w"))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(*sys.argv[2:6])
    else:
        main()

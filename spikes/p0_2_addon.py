"""mitmproxy addon for spike p0_2: write decrypted requests/responses and TLS failures as JSONL."""
import json, os
from mitmproxy import http, tls

OUT = os.environ["TW_FLOWS"]

def _w(rec):
    with open(OUT, "a") as f:
        f.write(json.dumps(rec) + "\n")

def response(flow: http.HTTPFlow):
    _w({"kind": "flow", "method": flow.request.method, "scheme": flow.request.scheme,
        "host": flow.request.pretty_host, "path": flow.request.path,
        "req_auth": flow.request.headers.get("Authorization"),
        "status": flow.response.status_code, "resp_body": flow.response.get_text()[:200]})

def error(flow: http.HTTPFlow):
    _w({"kind": "flow_error", "host": flow.request.pretty_host, "path": flow.request.path,
        "error": str(flow.error)})

def tls_failed_client(data: tls.TlsData):
    _w({"kind": "tls_failed_client", "error": str(data.conn.error)})

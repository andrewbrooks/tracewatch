"""Websocket recording in the proxy addon, driven with mitmproxy's own test flows (no network)."""

import importlib
import json
import os

import pytest
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketMessage
from wsproto.frame_protocol import Opcode

KEY = "6b" * 32


@pytest.fixture
def pa(tmp_path, monkeypatch):
    monkeypatch.setenv("TW_FLOWS", str(tmp_path / "flows.jsonl"))
    monkeypatch.setenv("TW_REDACT_KEY", KEY)
    for k in ("TW_SOFT_FLOWS_BYTES", "TW_MAX_FLOWS_BYTES", "TW_FLAGS_DIR"):
        monkeypatch.delenv(k, raising=False)
    import tracewatch.proxy_addon as mod

    mod = importlib.reload(mod)
    yield mod
    if mod._fd is not None:
        os.close(mod._fd)
        mod._fd = None


def recs(tmp_path):
    p = tmp_path / "flows.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def wsflow():
    f = tflow.twebsocketflow(messages=False)
    f.websocket.messages.clear()
    return f


def push(pa, f, content, from_client=True, text=True):
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT if text else Opcode.BINARY, from_client, content))
    pa.websocket_message(f)


def test_open_message_close_roundtrip_with_redaction(pa, tmp_path):
    f = wsflow()
    pa.websocket_start(f)
    push(pa, f, b'{"type":"echo","password":"CANARYpw0123456789","note":"VISMARKmsg","max_tokens":5}')
    push(pa, f, b"plain text with token=CANARYtok0123456789 and VISMARKplain", from_client=False)
    f.websocket.close_code, f.websocket.close_reason, f.websocket.closed_by_client = (
        1000,
        "bye password=CANARYclose0123456789",
        True,
    )
    pa.websocket_end(f)
    r = recs(tmp_path)
    assert [x["kind"] for x in r] == ["ws_open", "ws_message", "ws_message", "ws_close"]
    blob = json.dumps(r)
    for secret in ("CANARYpw0123456789", "CANARYtok0123456789", "CANARYclose0123456789"):
        assert secret not in blob
    assert "VISMARKmsg" in blob and "VISMARKplain" in blob and '\\"max_tokens\\":5' in blob
    m1, m2 = r[1], r[2]
    assert (m1["seq"], m1["dir"], m1["opcode"]) == (0, "c2s", "text") and (m2["seq"], m2["dir"]) == (1, "s2c")
    close = r[3]
    assert close["close_code"] == 1000 and close["clean"] and close["closed_by_client"]
    assert close["messages"] == {"c2s": 1, "s2c": 1}


def test_binary_is_described_not_stored(pa, tmp_path):
    f = wsflow()
    pa.websocket_start(f)
    push(pa, f, bytes(range(256)) * 4, text=False)
    body = recs(tmp_path)[1]["body"]
    assert body == {"size": 1024, "captured": False, "reason": "binary"}


def test_abnormal_closure_is_not_clean(pa, tmp_path):
    f = wsflow()
    pa.websocket_start(f)
    f.websocket.close_code = 1006
    pa.websocket_end(f)
    assert recs(tmp_path)[-1]["close_code"] == 1006 and recs(tmp_path)[-1]["clean"] is False


def test_close_without_any_code_is_not_clean(pa, tmp_path):
    f = wsflow()
    pa.websocket_start(f)
    f.websocket.close_code = None
    pa.websocket_end(f)
    assert recs(tmp_path)[-1]["clean"] is False


def test_per_message_cap_truncates_after_redaction(pa, tmp_path, monkeypatch):
    monkeypatch.setattr(pa, "WS_MSG_CAP", 60)
    f = wsflow()
    pa.websocket_start(f)
    push(pa, f, (b"x " * 30) + b"sk-ant-CANARYshape0123456789abcdef" + (b" y" * 40))
    body = recs(tmp_path)[1]["body"]
    assert body["truncated"] and len(body["text"]) <= 60 and "sk-ant" not in body["text"]


def test_connection_budget_keeps_metadata_but_stops_storing_text(pa, tmp_path, monkeypatch):
    monkeypatch.setattr(pa, "WS_BUDGET", 50)
    f = wsflow()
    pa.websocket_start(f)
    for _ in range(6):
        push(pa, f, b"0123456789" * 3)
    bodies = [r["body"] for r in recs(tmp_path) if r["kind"] == "ws_message"]
    assert bodies[0]["captured"] and bodies[1]["captured"]
    assert any(
        b.get("reason") == "websocket connection budget" and b["size"] == 30 and not b["captured"] for b in bodies
    )


def test_record_limit_suppresses_but_counts_everything(pa, tmp_path, monkeypatch):
    monkeypatch.setattr(pa, "WS_MAX_RECORDS", 3)
    f = wsflow()
    pa.websocket_start(f)
    for i in range(10):
        push(pa, f, f"m{i}".encode(), from_client=(i % 2 == 0))
    f.websocket.close_code = 1000
    pa.websocket_end(f)
    r = recs(tmp_path)
    assert sum(x["kind"] == "ws_message" for x in r) == 3
    close = r[-1]
    assert close["messages"] == {"c2s": 5, "s2c": 5} and close["suppressed"]["records"] == 7
    assert close["bytes"]["c2s"] + close["bytes"]["s2c"] == 20


def test_state_is_released_at_close_and_on_error(pa):
    f = wsflow()
    pa.websocket_start(f)
    assert f.id in pa._ws
    pa.websocket_end(f)
    assert f.id not in pa._ws
    g = wsflow()
    pa.websocket_start(g)
    pa.error(g)
    assert g.id not in pa._ws


def test_message_without_start_still_works(pa, tmp_path):
    f = wsflow()
    push(pa, f, b"hello")
    assert recs(tmp_path)[0]["kind"] == "ws_message"


def test_hard_cap_drops_messages_and_counts_them(tmp_path, monkeypatch):
    monkeypatch.setenv("TW_FLOWS", str(tmp_path / "flows.jsonl"))
    monkeypatch.setenv("TW_REDACT_KEY", KEY)
    monkeypatch.setenv("TW_MAX_FLOWS_BYTES", "20000")
    monkeypatch.delenv("TW_SOFT_FLOWS_BYTES", raising=False)
    import tracewatch.proxy_addon as mod

    mod = importlib.reload(mod)
    monkeypatch.setattr(mod, "RESERVE", 3000)
    f = wsflow()
    mod.websocket_start(f)
    for _ in range(300):
        push(mod, f, b"x" * 100)
    assert mod._dropped["ws_message"] > 0
    assert (tmp_path / "flows.jsonl").stat().st_size <= 20000
    os.close(mod._fd)
    mod._fd = None


def test_no_response_tee_on_101_upgrade(pa):
    f = tflow.tflow(resp=True)
    f.response.status_code = 101
    pa.responseheaders(f)
    assert f.id not in pa._streams and not f.response.stream
    g = tflow.tflow(resp=True)
    pa.responseheaders(g)
    assert g.id in pa._streams and callable(g.response.stream)

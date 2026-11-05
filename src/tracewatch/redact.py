"""Redaction applied BEFORE anything is written to disk. Pure functions; no I/O.

Each redacted value becomes ``[REDACTED:<kind>:<tag>]`` where ``tag`` is the first 8 hex chars of
HMAC-SHA256(run_key, value). The key lives only in memory (the recorder and the proxy process get it
through the environment) and is never written, so the tag cannot be used to confirm a guess after the
fact, but equal secrets get equal tags within a run (you can see "the same token was reused").

What it catches, and what it cannot:
  * names: header names, JSON keys, form/query/argv/env names that read as credentials (password,
    token, secret, api key, authorization, cookie, session, signature, ...). The VALUE is redacted
    whatever it looks like.
  * shapes: bearer/basic credentials, ``sk-...`` keys, AWS access key ids, GitHub/Slack/Google tokens,
    JWTs, private-key blocks, ``scheme://user:password@`` URLs, wherever they appear in text.
  * It is heuristic. A secret with a novel shape, sent under an innocuous name, is NOT caught. Treat
    run directories as sensitive anyway; redaction reduces exposure, it does not make them public.
Fail closed: callers must drop (not write) any record whose redaction raises.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections import Counter
from urllib.parse import parse_qsl, quote_plus

SENSITIVE_WORDS = frozenset(
    "password passwd pwd passphrase secret token apikey authorization auth credential credentials "
    "cookie signature session sessionid bearer".split()
)
SENSITIVE_PAIRS = frozenset(
    {
        ("api", "key"),
        ("access", "key"),
        ("secret", "key"),
        ("private", "key"),
        ("client", "secret"),
        ("auth", "key"),
        ("signing", "key"),
        ("encryption", "key"),
        ("ssh", "key"),
        ("master", "key"),
        ("session", "id"),
    }
)
TEXT_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/x-www-form-urlencoded",
    "+json",
    "+xml",
    "ndjson",
    "jsonl",
)
PROCESS_CAP = 1_000_000  # bodies larger than this are not captured at all (cannot be redacted cheaply/safely)
CRED_FLAGS = frozenset({"-u", "--user", "--proxy-user", "-U"})  # flags whose next argument is user:password


def _words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w for w in re.split(r"[^a-z0-9]+", spaced.lower()) if w]


def name_is_sensitive(name: str) -> bool:
    """True if a field/header/flag name reads as a credential. ``max_tokens`` is not; ``access_token`` is."""
    w = _words(name)
    return any(x in SENSITIVE_WORDS for x in w) or any(p in SENSITIVE_PAIRS for p in zip(w, w[1:], strict=False))


def is_textual(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in TEXT_TYPES)


_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@]*:)([^/\s@]+)(@)")
_BEARER = re.compile(r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=\-]{8,})")
_BASIC = re.compile(r"(?i)\b(Basic\s+)([A-Za-z0-9+/=]{8,})")
_SHAPES = (
    ("apikey", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("aws-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
)
# name <sep> value, in free text (JSON-ish, key=value, header lines, argv elements)
_KV = re.compile(r"""(?P<name>["']?[A-Za-z][\w.\-]*["']?)(?P<sep>\s*[:=]\s*)(?P<q>["']?)(?P<val>[^\s"'&;,<>)}\]\[]+)""")
_REDACTED = "[REDACTED:"
_TAG = re.compile(r"\[REDACTED:[A-Za-z0-9_\-]+:[0-9a-f]{8}\]")  # the exact shape Redactor.tag() produces


class Redactor:
    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(32)
        self.counts: Counter[str] = Counter()

    # ---- primitives
    def tag(self, kind: str, value: str) -> str:
        self.counts[kind] += 1
        h = hmac.new(self.key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]
        return f"{_REDACTED}{kind}:{h}]"

    def text(self, s: str) -> str:
        """Pattern-based redaction of free text. Idempotent: already-redacted spans are left alone."""
        if not s:
            return s
        s = _PRIVATE_KEY.sub(lambda m: self.tag("private-key", m.group(0)), s)
        s = _URL_USERINFO.sub(lambda m: m.group(1) + self.tag("url-password", m.group(2)) + m.group(3), s)
        s = _BEARER.sub(lambda m: m.group(1) + self.tag("bearer", m.group(2)), s)
        s = _BASIC.sub(lambda m: m.group(1) + self.tag("basic", m.group(2)), s)
        for kind, rx in _SHAPES:
            s = rx.sub(lambda m, k=kind: self.tag(k, m.group(0)), s)
        return self._kv_scan(s)

    def _kv_scan(self, s: str) -> str:
        """Redact the value of every sensitive `name<sep>value`. After a NON-sensitive pair, resume scanning
        inside its value: in `https://h/x?api_key=SECRET` the first match is `https`+`:`+`//h/x?api_key=...`
        and consuming all of it would hide the nested `api_key`."""
        out, pos = [], 0
        spans = [(t.start(), t.end()) for t in _TAG.finditer(s)]  # tags already written by earlier rules
        while True:
            m = _KV.search(s, pos)
            if not m:
                break
            inside = next((sp for sp in spans if sp[0] <= m.start() < sp[1]), None)
            if inside:  # a tag's own text ("bearer", "cookie"...) must never be scanned as a name/value
                out.append(s[pos : inside[1]])
                pos = inside[1]
                continue
            name = m.group("name").strip("\"'")
            tag_follows = s[m.end() : m.end() + 1 + len(_REDACTED)].lstrip().startswith(_REDACTED)
            if name_is_sensitive(name) and not tag_follows:  # tag_follows: val is just a scheme word (`Bearer`)
                out.append(s[pos : m.start("val")])
                out.append(self.tag("kv", m.group("val")))
                pos = m.end()
            else:
                out.append(s[pos : m.end("sep")])
                pos = m.end("sep")
        out.append(s[pos:])
        return "".join(out)

    # ---- structured places
    def header(self, name: str, value: str) -> str:
        ln = name.lower()
        if ln == "cookie":
            return "; ".join(self._cookie_pair(p) for p in value.split(";"))
        if ln == "set-cookie":
            first, sep, rest = value.partition(";")
            return self._cookie_pair(first) + sep + self.text(rest)
        if ln in ("authorization", "proxy-authorization"):
            scheme, sp, cred = value.partition(" ")
            return f"{scheme}{sp}{self.tag('auth', cred)}" if cred else self.tag("auth", value)
        if name_is_sensitive(name):
            return self.tag("header", value)
        return self.url(value) if ln in ("location", "referer", "origin") else self.text(value)

    def _cookie_pair(self, pair: str) -> str:
        k, eq, v = pair.strip().partition("=")
        return f"{k}{eq}{self.tag('cookie', v)}" if eq and v else pair.strip()

    def headers(self, items) -> list[list[str]]:
        return [[k, self.header(k, v)] for k, v in items]

    def url(self, u: str) -> str:
        base, q, rest = u.partition("?")
        if q:
            query, h, frag = rest.partition("#")
            parts = []
            for piece in query.split("&"):
                k, eq, v = piece.partition("=")
                parts.append(f"{k}={self.tag('query', v)}" if eq and v and name_is_sensitive(k) else piece)
            u = base + q + "&".join(parts) + h + frag
        return self.text(u)

    def json_value(self, obj, key: str | None = None):
        """Structure-aware: a sensitive key redacts its STRING value (numbers/bools/null are not secrets)."""
        if isinstance(obj, dict):
            return {k: self.json_value(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.json_value(v, key) for v in obj]
        if isinstance(obj, str):
            return self.tag("json", obj) if key is not None and name_is_sensitive(key) else self.text(obj)
        return obj

    def _json_lines(self, text: str, prefix: str = "") -> str:
        """Line-oriented JSON (ndjson, SSE `data:` lines): redact each JSON payload structurally."""
        out = []
        for line in text.split("\n"):
            body = line[len(prefix) :].strip() if line.startswith(prefix) else None
            if body:
                try:
                    out.append(
                        prefix
                        + (" " if prefix else "")
                        + json.dumps(self.json_value(json.loads(body)), separators=(",", ":"), ensure_ascii=False)
                    )
                    continue
                except ValueError:
                    pass
            out.append(self.text(line))
        return "\n".join(out)

    def body_text(self, content_type: str, text: str) -> str:
        ct = (content_type or "").lower()
        if "event-stream" in ct:
            return self._json_lines(text, "data:")
        if "ndjson" in ct or "jsonl" in ct:
            return self._json_lines(text)
        if "json" in ct:
            try:
                return json.dumps(self.json_value(json.loads(text)), separators=(",", ":"), ensure_ascii=False)
            except ValueError:
                return self.text(text)
        if "x-www-form-urlencoded" in ct:
            # A body labelled "form" is not necessarily a form (curl --data-binary @key.pem says so by default). Parsing
            # it splits a raw PEM into a "key" that was never redacted and re-encodes it, which also defeats the
            # multi-line private-key pattern: so PEM blocks go first, and keys are redacted like values.
            text = _PRIVATE_KEY.sub(lambda m: self.tag("private-key", m.group(0)), text)
            pairs = parse_qsl(text, keep_blank_values=True)
            return "&".join(
                f"{quote_plus(self.text(k))}="
                + quote_plus(self.tag("form", v) if name_is_sensitive(k) and v else self.text(v))
                for k, v in pairs
            )
        return self.text(text)

    def body(self, content_type: str, raw_size: int, get_text, cap: int) -> dict:
        """Capture record for a message body. Redact FIRST, truncate AFTER, so a cut can never expose a
        prefix of a raw secret. Non-text and oversized bodies are described, never stored."""
        out = {"size": raw_size, "content_type": content_type or None}
        if raw_size == 0:
            return {**out, "captured": False, "reason": "empty"}
        if not is_textual(content_type):
            return {**out, "captured": False, "reason": "non-text"}
        if raw_size > PROCESS_CAP:
            return {**out, "captured": False, "reason": "too large to redact"}
        red = self.body_text(content_type, get_text())
        return {**out, "captured": True, "truncated": len(red) > cap, "text": red[:cap]}

    # ---- argv / env / tracee
    def argv(self, argv: list[str]) -> list[str]:
        out, redact_next = [], False
        for a in argv:
            if redact_next:
                out.append(self.tag("argv", a))
                redact_next = False
                continue
            m = re.match(r"^--?([A-Za-z][\w\-]*)=(.*)$", a, re.S)
            if m and (name_is_sensitive(m.group(1)) or a.split("=")[0] in CRED_FLAGS):
                out.append(a.split("=", 1)[0] + "=" + self.tag("argv", m.group(2)))
                continue
            flag = re.match(r"^--?([A-Za-z][\w\-]*)$", a)
            if flag and (name_is_sensitive(flag.group(1)) or a in CRED_FLAGS):
                redact_next = True
                out.append(a)
                continue
            out.append(self.text(a))
        return out

    def env_entry(self, entry: str) -> str:
        k, eq, v = entry.partition("=")
        if eq and name_is_sensitive(k):
            return f"{k}={self.tag('env', v)}"
        return self.text(entry)

    def tracee_event(self, ev: dict) -> dict:
        for a in ev.get("args", []):
            v = a.get("value")
            if a.get("name") == "argv" and isinstance(v, list):
                a["value"] = self.argv([str(x) for x in v])
            elif a.get("name") == "env" and isinstance(v, list):
                a["value"] = [self.env_entry(str(x)) for x in v]
            elif isinstance(v, str):
                a["value"] = self.text(v)
            elif isinstance(v, list):
                a["value"] = [self.text(x) if isinstance(x, str) else x for x in v]
        return ev

    def tracee_line(self, raw: bytes) -> bytes:
        """One docker-log line -> the redacted line to store. Never returns the raw text of a line it
        could not parse as an event: non-JSON output is stored as redacted text."""
        line = raw.decode("utf-8", "replace").rstrip("\n")
        try:
            ev = json.loads(line)
        except ValueError:
            return (json.dumps({"kind": "tracee_text", "text": self.text(line)}) + "\n").encode()
        if isinstance(ev, dict):
            ev = self.tracee_event(ev)
        return (json.dumps(ev, separators=(",", ":")) + "\n").encode()

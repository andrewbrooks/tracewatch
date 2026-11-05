import json

import pytest

from tracewatch.redact import Redactor, name_is_sensitive

KEY = b"k" * 32
SECRETS = {
    "bearer": "Bearer abcDEF123456789xyz",
    "sk": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "ghp": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "slack": "xoxb-1234567890-abcdefghij",
    "google": "AIzaSyA-abcdefghijklmnopqrstuvwxyz012345",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
}


@pytest.fixture
def r():
    return Redactor(KEY)


def gone(out: str, *secrets: str):
    for s in secrets:
        assert s not in out, f"leaked {s!r} in {out!r}"


@pytest.mark.parametrize("name", list(SECRETS))
def test_secret_shapes_redacted_in_free_text(r, name):
    s = SECRETS[name]
    secret = s.split(" ", 1)[-1]
    out = r.text(f"before {s} after")
    gone(out, secret)
    assert out.startswith("before ") and out.endswith(" after") and "[REDACTED:" in out


def test_private_key_block_and_truncated_block(r):
    full = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    gone(r.text(f"x {full} y"), "MIIEowIBAAKCAQEA")
    gone(r.text("x -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg"), "MIIEvQIBADANBg")  # cut off mid-block


def test_url_userinfo_password(r):
    out = r.text("fetch https://alice:hunter2pw@example.com/path")
    gone(out, "hunter2pw")
    assert "alice" in out and "example.com/path" in out


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "api_key",
        "apiKey",
        "access_token",
        "client_secret",
        "X-Api-Key",
        "Authorization",
        "set-cookie",
        "refresh_token",
        "SESSION_ID",
        "aws_secret_access_key",
    ],
)
def test_sensitive_names(name):
    assert name_is_sensitive(name)


@pytest.mark.parametrize(
    "name",
    [
        "max_tokens",
        "input_tokens",
        "author",
        "authority",
        "monkey",
        "key",
        "keyboard",
        "content-type",
        "user-agent",
        "anthropic-version",
        "x-request-id",
        "model",
    ],
)
def test_non_sensitive_names(name):
    assert not name_is_sensitive(name)


def test_kv_in_text_redacts_value_keeps_structure(r):
    out = r.text('{"model":"m","max_tokens":1024,"password":"hunter2pw","note":"hi"} a=1&token=abc12345&b=2')
    gone(out, "hunter2pw", "abc12345")
    assert '"max_tokens":1024' in out and '"model":"m"' in out and "a=1" in out and "b=2" in out


def test_authorization_header_keeps_scheme_only(r):
    out = r.header("Authorization", "Bearer abcDEF123456789xyz")
    assert out.startswith("Bearer [REDACTED:auth:") and "abcDEF" not in out
    assert r.header("authorization", "rawtokenvalue").startswith("[REDACTED:auth:")
    assert r.header("Proxy-Authorization", "Basic dXNlcjpwYXNz").startswith("Basic [REDACTED:")


def test_cookie_and_set_cookie_keep_names_and_attrs(r):
    c = r.header("Cookie", "sid=abc123secret; theme=dark")
    gone(c, "abc123secret", "dark")
    assert "sid=" in c and "theme=" in c
    sc = r.header("Set-Cookie", "session=zzTOPsecret99; Path=/; HttpOnly; Secure")
    gone(sc, "zzTOPsecret99")
    assert "Path=/" in sc and "HttpOnly" in sc


def test_other_headers_keep_value_but_patterns_still_apply(r):
    assert r.header("User-Agent", "curl/8.5.0") == "curl/8.5.0"
    gone(r.header("X-Forwarded", "token=abcdef123456"), "abcdef123456")
    gone(r.header("X-Api-Key", "plainvalue-123"), "plainvalue-123")
    gone(r.header("Referer", "https://h/p?api_key=sekrit9999&q=1"), "sekrit9999")


def test_url_query_sensitive_params_only(r):
    out = r.url("/v1/x?api_key=sekrit9999&q=visible&access_token=tok12345678#frag")
    gone(out, "sekrit9999", "tok12345678")
    assert "q=visible" in out and out.endswith("#frag")


def test_json_body_structure_aware(r):
    body = {
        "user": "bob",
        "password": "pw-1",
        "nested": {"api_key": "k-2", "list": [{"token": "t-3"}, "plain"]},
        "max_tokens": 5,
        "flag": True,
        "secret": None,
        "n": {"authorization": 12345},
    }
    out = r.body_text("application/json", json.dumps(body))
    gone(out, "pw-1", "k-2", "t-3")
    parsed = json.loads(out)
    assert parsed["user"] == "bob" and parsed["max_tokens"] == 5 and parsed["flag"] is True
    assert parsed["secret"] is None and parsed["n"]["authorization"] == 12345  # non-strings are not secrets
    assert parsed["nested"]["list"][1] == "plain"


def test_json_string_values_still_pattern_scanned(r):
    out = r.body_text("application/json", json.dumps({"note": f"here is {SECRETS['sk']} ok"}))
    gone(out, SECRETS["sk"])


def test_invalid_json_falls_back_to_text(r):
    gone(r.body_text("application/json", '{"password": "hunter2pw", broken'), "hunter2pw")


def test_form_body(r):
    out = r.body_text("application/x-www-form-urlencoded", "user=bob&password=hunter2pw&note=a+b")
    gone(out, "hunter2pw")
    assert "user=bob" in out


def test_truncation_happens_after_redaction(r):
    secret = SECRETS["sk"]
    text = "x" * 89 + " " + secret + "y" * 50
    rec = r.body("text/plain", len(text), lambda: text, cap=100)  # cut falls inside the secret
    assert rec["truncated"] and secret[:8] not in rec["text"].replace("[REDACTED", "")
    gone(rec["text"], secret[:12])


def test_body_policy_non_text_empty_and_huge(r):
    assert r.body("image/png", 5000, lambda: "x", 100)["reason"] == "non-text"
    assert r.body(None, 0, lambda: "", 100)["reason"] == "empty"
    big = r.body("text/plain", 2_000_000, lambda: pytest.fail("must not read huge bodies"), 100)
    assert not big["captured"] and "too large" in big["reason"]


def test_argv_flags_and_embedded_credentials(r):
    out = r.argv(
        [
            "curl",
            "--token",
            "abc12345secret",
            "-u",
            "bob:pw12345",
            "--password=hunter2pw",
            "-H",
            "Authorization: Bearer abcDEF123456789xyz",
            "https://h/x?api_key=zz99aa11&q=1",
            "-o",
            "/dev/null",
        ]
    )
    gone(" ".join(out), "abc12345secret", "pw12345", "hunter2pw", "abcDEF123456789xyz", "zz99aa11")
    assert out[0] == "curl" and "-o" in out and "/dev/null" in out and "--token" in out


def test_argv_trailing_sensitive_flag_does_not_crash(r):
    assert r.argv(["prog", "--token"]) == ["prog", "--token"]


def test_env_entries(r):
    assert r.env_entry("HOME=/home/a") == "HOME=/home/a"
    gone(r.env_entry("GITHUB_TOKEN=abc12345"), "abc12345")
    gone(r.env_entry("DB=postgres://u:pw99999@h/db"), "pw99999")


def test_tags_stable_per_key_and_distinct_otherwise():
    a, b = Redactor(KEY), Redactor(KEY)
    assert a.text("token=samevalue1") == b.text("token=samevalue1")  # same key, same secret -> same tag
    assert a.text("token=samevalue1") != a.text("token=othervalue")
    assert a.text("token=samevalue1") != Redactor(b"z" * 32).text("token=samevalue1")


def test_tag_does_not_contain_secret(r):
    assert "hunter2pw" not in r.tag("kv", "hunter2pw")


def test_idempotent(r):
    once = r.text(f"Authorization: Bearer abcDEF123456789xyz and {SECRETS['sk']} password=hunter2pw")
    assert r.text(once) == once


def test_counts_are_recorded(r):
    r.text("password=hunter2pw")
    r.header("Authorization", "Bearer x")
    assert r.counts["kv"] == 1 and r.counts["auth"] == 1


def test_tracee_event_redacts_argv_env_and_strings(r):
    ev = {
        "eventName": "sched_process_exec",
        "processId": 5,
        "args": [
            {"name": "argv", "value": ["curl", "--token", "abc12345secret"]},
            {"name": "env", "value": ["PATH=/bin", "API_KEY=zz99aa11"]},
            {"name": "pwd", "value": "/home/a"},
            {"name": "dev", "value": 123},
        ],
    }
    out = r.tracee_event(ev)
    s = json.dumps(out)
    gone(s, "abc12345secret", "zz99aa11")
    assert out["processId"] == 5 and out["args"][2]["value"] == "/home/a" and out["args"][3]["value"] == 123
    assert "PATH=/bin" in out["args"][1]["value"]


def test_tracee_line_non_json_is_redacted_text_not_raw(r):
    out = json.loads(r.tracee_line(b"panic: failed with token=abc12345secret\n"))
    assert out["kind"] == "tracee_text" and "abc12345secret" not in out["text"]


def test_tracee_line_roundtrip_keeps_fields_used_by_join(r):
    ev = {
        "timestamp": 1,
        "processId": 9,
        "processName": "curl",
        "eventName": "net_tcp_connect",
        "args": [{"name": "dst_port", "value": 443}],
    }
    assert json.loads(r.tracee_line(json.dumps(ev).encode())) == ev


def test_nested_pair_inside_non_sensitive_value_is_found(r):
    """Regression: `https:` + `//h/x?api_key=...` used to be consumed as one non-sensitive pair."""
    gone(r.text("see https://h/x?api_key=zz99aa11&q=1 now"), "zz99aa11")
    gone(r.text("a=b:c=token=abc12345"), "abc12345")
    gone(r.text("redirect=/cb?code=1&access_token=abc12345xyz"), "abc12345xyz")


def test_ordinary_words_containing_sk_are_not_mangled(r):
    text = "the risk-assessment-framework-document and disk-based-storage-system-config"
    assert r.text(text) == text


def test_every_tag_has_the_exact_shape_and_none_is_nested(r):
    """Regression: the kv scan used to re-scan the inside of tags written by earlier rules (a tag contains
    words like 'bearer'), producing '[REDACTED:bearer:[REDACTED:kv:...]]'. Stable, so idempotence tests passed."""
    import re

    inputs = [
        "Authorization: Bearer abcDEF123456789xyz",
        "curl -H 'Authorization: Bearer abcDEF123456789xyz' https://u:pw99999@h/x?api_key=zz99aa11&q=1",
        "cookie: sid=abc; Set-Cookie: session=zz99aa11bb; token=abcdef123456 password=hunter2pw",
        f"x {SECRETS['sk']} {SECRETS['jwt']} {SECRETS['aws']} Basic dXNlcjpwYXNzd29yZA==",
        '{"authorization":"Bearer abcDEF123456789xyz","cookie":"a=b"}',
    ]
    shape = re.compile(r"\[REDACTED:[A-Za-z0-9_\-]+:[0-9a-f]{8}\]")
    for text in inputs:
        out = r.text(text)
        assert out.count("[REDACTED:") == len(shape.findall(out)), out  # every opener is a complete, well-formed tag
        assert "[REDACTED:" not in shape.sub("", out), out  # nothing left over, nothing nested


def test_a_value_after_a_scheme_word_keeps_exactly_one_tag(r):
    out = r.text("Authorization: Bearer abcDEF123456789xyz")
    assert out.startswith("Authorization: Bearer [REDACTED:bearer:") and out.count("[REDACTED:") == 1

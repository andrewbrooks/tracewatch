"""TEST ONLY. Sabotages redaction (tags keep the secret) in every Python process of a run, to prove the
canary test fails when redaction is broken. Never on the path in normal use."""

import tracewatch.redact as r

r.Redactor.tag = lambda self, kind, value: value

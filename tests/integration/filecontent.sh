#!/bin/bash
# End to end: files the target created or wrote are captured (inert, redacted, even if deleted after use);
# a credential file it only read is not, and its content appears nowhere in the run directory.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd); cd "$HERE"; OUT=out/filecontent
rm -rf "$OUT"
CRED_DIR=/tmp/tw_fc_cred_$$
mkdir -p "$CRED_DIR" && printf 'SECRETKEY-DO-NOT-CAPTURE-7f3a\n' > "$CRED_DIR/id_rsa"
.venv/bin/tracewatch record --quiet --out "$OUT" --name fc -- tests/fixtures/filecontent_workload.sh "$CRED_DIR/id_rsa"
rc=$?
rm -rf "$CRED_DIR"
[ $rc = 0 ] || { echo "FAIL the recording itself failed (exit $rc)"; exit 1; }
.venv/bin/python tests/integration/filecontent_check.py "$OUT/fc"

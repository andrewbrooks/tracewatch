#!/bin/bash
# Mutation test: with redaction sabotaged, the canary test MUST fail and report leaks.
HERE=$(cd "$(dirname "$0")/../.." && pwd)
out=$(PYTHONPATH="$HERE/tests/integration/mutation" "$HERE/tests/integration/canary.sh" 2>&1)
echo "$out" | grep -E "LEAK|FAIL" | head -12
if echo "$out" | grep -q "FAIL NO planted secret" && echo "$out" | grep -q "LEAK:"; then
  echo "MUTATION DETECTED: the canary test fails when redaction is broken (good)"; exit 0
fi
echo "MUTATION SURVIVED: the canary test did NOT catch broken redaction (the test is worthless)"; exit 1

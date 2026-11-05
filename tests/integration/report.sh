#!/bin/bash
# Record the demo workload for real, then check that the report tells the truth about it.
set -u
HERE=$(cd "$(dirname "$0")/../.." && pwd)
"$HERE/tests/fixtures/demo.sh" >/dev/null 2>&1
"$HERE/.venv/bin/python" "$HERE/tests/integration/report_check.py" "$HERE/out/demo/runs/demo"

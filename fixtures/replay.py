"""Synthetic protocol replay for collector examples; it does not launch a browser."""

import os
import sys
from pathlib import Path

if os.environ.get("CAMOUFOX_TRACE") != "1":
    raise SystemExit("CAMOUFOX_TRACE=1 is required")

print("synthetic child stdout")
print("unrelated child stderr", file=sys.stderr)
for line in Path(__file__).with_name("pilot.jsonl").read_text(encoding="utf-8").splitlines():
    print("[synthetic driver] CAMOUFOX_TRACE " + line, file=sys.stderr)

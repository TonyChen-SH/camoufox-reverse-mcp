"""Replay synthetic engine fragments to exercise stderr collection without a browser."""

import os
from pathlib import Path
import sys

if os.environ.get('CAMOUFOX_ENGINE_TRACE') != '1':
    raise SystemExit('CAMOUFOX_ENGINE_TRACE=1 is required')

for line in Path(__file__).with_name('engine.jsonl').read_text(encoding='ascii').splitlines():
    print('CAMOUFOX_TRACE ' + line, file=sys.stderr)

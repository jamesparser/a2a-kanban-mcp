#!/usr/bin/env python3
"""Generate the shared kanban CEK on the board host and print it as base64.

The CEK is a SHARED secret (every roster principal holds it) because a card is
shared state: the owner moves it, everyone lists it. It is printed ONCE here
and written to each host's 0600 key file. Never logged after that.
"""
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, '/opt/kanban-mcp')
import kanban_enc

OUT = Path('/opt/kanban-mcp/kanban_cek.json')
BOARD = 'omega-kanban-20261110'

if OUT.exists() and '--force' not in sys.argv:
    print('EXISTS ' + json.dumps(json.loads(OUT.read_text())['cek']))
    sys.exit(0)

cek = kanban_enc.new_cek()
digest = kanban_enc.write_key_file(OUT, cek, BOARD)
print('GENERATED sha256=' + digest)
print('CEK ' + base64.b64encode(cek).decode())

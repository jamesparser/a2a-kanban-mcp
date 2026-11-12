#!/usr/bin/env python3
"""Generate per-principal AES-256-GCM content keys (CEKs) for the mesh fleet.

Runs ON the hub (rci-vps / omega, root). Creates one random 32-byte CEK per
roster principal (plus the hub itself), then writes:
  - ALL keys -> /opt/a2a-omega-mesh-mcp/enc_keys.json   (hub copy, 0600)
  - a per-principal bundle under /opt/a2a-omega-mesh-mcp/distribute/<name>.json
    containing ONLY: the principal's own CEK + the hub's CEK.
Distribution to each device happens over the existing pinned SSH channel
(scp by the operator); devices store their bundle at /opt/a2a-omega-mesh-mcp/
enc_keys.json (or $HOME path on phones) with 0600.

Never prints key material.
"""
import base64
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mesh_enc

ROSTER = os.environ.get('SIGNED_BOARD_ROSTER', '/opt/mesh-board-prod-20261031/roster.json')
OUT_DIR = Path(os.environ.get('MESH_ENC_DIR', '/opt/a2a-omega-mesh-mcp'))
HUB = 'rci-vps'


def main():
    roster = json.loads(Path(ROSTER).read_text())
    principals = sorted(roster.keys())
    if HUB not in principals:
        sys.exit('hub %s missing from roster' % HUB)

    # Reuse existing keys if the hub copy already exists (stable IDs across
    # redeploys; rotation is a separate operator action).
    keyfile = OUT_DIR / 'enc_keys.json'
    if keyfile.exists():
        existing = mesh_enc.EncKeyFile(keyfile)
        keys = dict(existing.keys)
        print('reusing existing CEKs for:', ', '.join(sorted(keys.keys())))
    else:
        keys = {name: mesh_enc.new_key() for name in principals}

    missing = [p for p in principals if p not in keys]
    if missing:
        # A principal joined after first generation: add CEKs only for the new ones.
        for p in missing:
            keys[p] = mesh_enc.new_key()
        print('added new CEKs for:', ', '.join(missing))

    digest = mesh_enc.write_key_file(keyfile, keys)
    os.chmod(OUT_DIR, 0o700)
    dist = OUT_DIR / 'distribute'
    dist.mkdir(mode=0o700, exist_ok=True)
    for name in keys:
        if name == HUB:
            continue
        bundle = {name: keys[name], HUB: keys[HUB]}
        mesh_enc.write_key_file(dist / (name + '.json'), bundle)
    print('hub keyfile:', str(keyfile), 'sha16:', digest)
    print('per-principal bundles:', str(dist))
    for name in sorted(keys):
        print('fingerprint', name, hashlib.sha256(keys[name]).hexdigest()[:12])


if __name__ == '__main__':
    main()

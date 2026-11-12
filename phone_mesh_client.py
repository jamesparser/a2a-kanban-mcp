#!/usr/bin/env python3
"""Phone-side encrypted mesh client (Termux).

Runs on exodus / s24 / s21fe / note8. Talks to the omega signed board through
a per-phone SSH -L tunnel (mesh-relay@omega, permitopen 127.0.0.1:18792 only),
so the phone never needs Tailscale and never opens a new port.

Own identity: signs with the phone's on-box Ed25519 key (roster principal =
phone name); encrypts outbound bodies with the RECIPIENT's CEK (AES-256-GCM)
and decrypts inbound with its own CEK (per-recipient confidentiality).

Subcommands:
  poll              one poll cycle: read first unacked -> receipt -> print
  send TO BODY      post an encrypted signed request
  respond ID BODY   post an encrypted signed response
  ack ID            ack a receipted message
  daemon [N]        loop poll every N sec (default 120) until killed

Env/config (defaults shown):
  PHONE_PRINCIPAL   s24
  PHONE_KEY         ~/work/mesh-board-pilot-20261030/ssh/id_ed25519  (s24/exodus)
                    ~/.ssh/id_ed25519                                (note8)
                    ~/.ssh/id_mesh_ed25519                           (s21fe)
  PHONE_ENC_KEYS    ~/a2a-omega-mesh-mcp/enc_keys.json
  PHONE_TUNNEL_PORT 18793  (local forwarded port to omega board)
  PHONE_BOARD_VIA   191.96.166.144  (omega public ssh IP)
  PHONE_BOARD_SSH_P 24133    (omega public ssh port)
  PHONE_DB          ~/a2a-omega-mesh-mcp/receipts.db
"""
import base64
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mesh_enc

HOME = Path.home()
PRINCIPAL = os.environ.get('PHONE_PRINCIPAL', 's24')
KEY = os.path.expanduser(os.environ.get(
    'PHONE_KEY', '~/work/mesh-board-pilot-20261030/ssh/id_ed25519'))
ENC_KEYS = os.path.expanduser(os.environ.get(
    'PHONE_ENC_KEYS', '~/a2a-omega-mesh-mcp/enc_keys.json'))
DB = os.path.expanduser(os.environ.get(
    'PHONE_DB', '~/a2a-omega-mesh-mcp/receipts.db'))
WORKDIR = Path(os.path.expanduser('~/a2a-omega-mesh-mcp'))
TUNNEL_PORT = int(os.environ.get('PHONE_TUNNEL_PORT', '18793'))
VIA_HOST = os.environ.get('PHONE_BOARD_VIA', '191.96.166.144')
VIA_PORT = int(os.environ.get('PHONE_BOARD_SSH_P', '24133'))

NAMESPACE = 'mesh-board-prod-v2'
BOARD = 'omega-mesh-prod-20261031'
ROSTER = json.loads((WORKDIR / 'roster.json').read_text())
ROSTER_KEYS = {n: p['key'] for n, p in ROSTER.items()}
ENCKEYS = mesh_enc.EncKeyFile(ENC_KEYS)

Path(DB).parent.mkdir(parents=True, exist_ok=True)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def _sign(envelope):
    with tempfile.TemporaryDirectory(dir=str(Path(WORKDIR))) as td:
        f = Path(td) / 'msg'
        f.write_bytes(_canonical(envelope))
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', KEY, '-n', NAMESPACE, str(f)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return base64.b64encode(Path(str(f) + '.sig').read_bytes()).decode()


def _verify(peer, data, sig_b64):
    if peer not in ROSTER_KEYS:
        return False
    with tempfile.TemporaryDirectory(dir=str(Path(WORKDIR))) as td:
        p = Path(td)
        (p / 'signers').write_text(peer + ' ' + ROSTER_KEYS[peer] + '\n')
        (p / 'sig').write_bytes(base64.b64decode(sig_b64))
        r = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(p / 'signers'),
                            '-I', peer, '-n', NAMESPACE, '-s', str(p / 'sig')],
                           input=data, capture_output=True, timeout=10)
        return r.returncode == 0


def _ensure_tunnel():
    """Start the SSH -L tunnel if the local port is not answering."""
    try:
        s = socket.create_connection(('127.0.0.1', TUNNEL_PORT), 1.0)
        s.close()
        return True
    except OSError:
        pass
    subprocess.Popen(
        ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
         '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ExitOnForwardFailure=yes',
         '-i', KEY, '-o', 'IdentitiesOnly=yes', '-p', str(VIA_PORT),
         '-f', '-N', '-L', '%d:127.0.0.1:18792' % TUNNEL_PORT,
         'mesh-relay@' + VIA_HOST],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    try:
        s = socket.create_connection(('127.0.0.1', TUNNEL_PORT), 2.0)
        s.close()
        return True
    except OSError:
        return False


def _rpc(wire):
    import http.client
    c = http.client.HTTPConnection('127.0.0.1', TUNNEL_PORT, timeout=15)
    body = json.dumps(wire, sort_keys=True, separators=(',', ':')).encode()
    c.request('POST', '/v2/rpc', body=body, headers={'Content-Type': 'application/json'})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, (json.loads(data) if data else {})


def _envelope(op, payload, mid=None, lifetime=120):
    now = int(time.time())
    return {'v': 2, 'board': BOARD, 'principal': PRINCIPAL, 'id': mid or str(uuid.uuid4()),
            'issued': now, 'expires': now + lifetime, 'op': op, 'payload': payload}


def _receipt_db():
    d = sqlite3.connect(DB)
    d.execute('PRAGMA synchronous=FULL')
    d.execute('CREATE TABLE IF NOT EXISTS received(id TEXT PRIMARY KEY, digest TEXT, sender TEXT, body TEXT, ts INTEGER)')
    d.commit()
    return d


def post(to, body, kind='request', parent=None):
    if ENCKEYS is None:
        return {'error': 'enc keys missing'}
    try:
        rkey = ENCKEYS.get(to)
    except KeyError as ex:
        return {'error': str(ex)}
    mid = str(uuid.uuid4())
    wire_body = mesh_enc.encrypt(rkey, PRINCIPAL, to, mid, body)
    payload = {'to': to, 'kind': kind, 'parent': parent, 'body': wire_body, 'ttl': 600,
               'dedupe': ('phone-' + PRINCIPAL + '-' + hashlib.sha256(body.encode()).hexdigest()[:16]) if kind == 'request' else None}
    e = _envelope('post', payload, mid=mid)
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    return {'http': st, 'result': resp.get('result', resp), 'id': mid, 'encrypted': True}


def read_one():
    e = _envelope('inbox', {})
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    if st != 200:
        return {'error': 'inbox rpc failed', 'http': st}
    msgs = resp.get('result', {}).get('messages', [])
    if not msgs:
        return {'empty': True}
    w = msgs[0]
    ev = w['envelope']
    sender = ev['principal']
    ok = _verify(sender, _canonical(ev), w['signature'])
    body_wire = ev['payload'].get('body', '')
    out = {'id': ev['id'], 'from': sender, 'kind': ev['payload'].get('kind'),
           'parent': ev['payload'].get('parent'), 'signature_valid': ok}
    if mesh_enc.is_encrypted(body_wire):
        try:
            pt = mesh_enc.decrypt(ENCKEYS.get(PRINCIPAL), sender, PRINCIPAL, ev['id'], body_wire)
            body = pt.decode('utf-8', errors='replace')
            out['encrypted'] = True
        except Exception as ex:
            body = ''
            out['encrypted'] = True
            out['decryption_error'] = type(ex).__name__
    else:
        body = body_wire
        out['encrypted'] = False
    out['body'] = body
    d = _receipt_db()
    try:
        with d:
            d.execute('INSERT OR REPLACE INTO received VALUES(?,?,?,?,?)',
                      (ev['id'], hashlib.sha256(_canonical(ev)).hexdigest(), sender, body, int(time.time())))
    finally:
        d.close()
    out['durably_received'] = True
    return out


def ack(mid):
    d = _receipt_db()
    try:
        have = d.execute('SELECT 1 FROM received WHERE id=?', (mid,)).fetchone()
    finally:
        d.close()
    if not have:
        return {'error': 'no durable receipt; read first'}
    e = _envelope('ack', {'id': mid})
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    return {'http': st, 'result': resp.get('result', resp)}


def respond(mid, body):
    d = _receipt_db()
    try:
        row = d.execute('SELECT sender FROM received WHERE id=?', (mid,)).fetchone()
    finally:
        d.close()
    if not row:
        return {'error': 'no durable receipt for ' + mid}
    return post(row[0], body, kind='response', parent=mid)


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else 'poll'
    if not _ensure_tunnel():
        print(json.dumps({'error': 'tunnel to omega board unavailable'}))
        sys.exit(1)
    if cmd == 'send' and len(args) >= 3:
        print(json.dumps(post(args[1], ' '.join(args[2:]))))
    elif cmd == 'respond' and len(args) >= 3:
        print(json.dumps(respond(args[1], ' '.join(args[2:]))))
    elif cmd == 'ack' and len(args) >= 2:
        print(json.dumps(ack(args[1])))
    elif cmd == 'poll':
        print(json.dumps(read_one()))
    elif cmd == 'daemon':
        interval = int(args[1]) if len(args) > 1 else 120
        while True:
            try:
                r = read_one()
                if not r.get('empty'):
                    print(time.strftime('%F %T'), json.dumps(r)[:400], flush=True)
                    if r.get('parent') is None and r.get('id') and r.get('signature_valid'):
                        # Auto-ack only after durable receipt; reply is the agent's job.
                        pass
            except Exception as ex:
                print(time.strftime('%F %T'), 'cycle error', type(ex).__name__, str(ex)[:120], flush=True)
            time.sleep(interval)
    else:
        print(__doc__)


if __name__ == '__main__':
    main()

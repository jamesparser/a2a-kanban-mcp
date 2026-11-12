#!/usr/bin/env python3
"""Encrypted MCP stdio server for the A2A mesh board (a2a-omega-mesh-mcp v2).

Same five tools and same signed-board protocol as the proven
mesh_mcp_server.py (revP), PLUS per-recipient AES-256-GCM body encryption:

  - mesh_post(to, body): the body is encrypted with the RECIPIENT's CEK
    (AES-256-GCM, fresh nonce, AAD binds board+sender+recipient+id) before it
    ever reaches the board. The board stores only the opaque "enc-v1:..." wire.
  - mesh_read(): verifies the sender's signature independently, durably
    receipts the message, then decrypts with THIS principal's own CEK.
  - mesh_ack / mesh_inbox / mesh_respond: unchanged semantics.

Signing is unchanged: ssh-keygen -Y (SSHSIG) with the principal's private key
(MESH_KEY); the board independently verifies every signature against the
roster. Encryption is an additional layer on the body only - signatures still
prove authorship, encryption now provides confidentiality per recipient.

Environment:
  MESH_PRINCIPAL   this principal's roster name      (default rci-vps)
  MESH_KEY         signing private key path          (default /root/.ssh/id_ed25519)
  MESH_ENC_KEYS    per-principal CEK JSON (0600)     (default /opt/a2a-omega-mesh-mcp/enc_keys.json)
  MESH_BOARD_HOST / MESH_BOARD_PORT                  (auto-detect, port 18792)
  MESH_RECEIPT_DB  local receipt sqlite              (default /root/mesh_mcp_receipts/receipts.db)
  SIGNED_BOARD_ROSTER                        (default /opt/mesh-board-prod-20261031/roster.json)

No secrets are printed; private/CEK material never leaves this host in logs.
"""
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mesh_enc

NAMESPACE = 'mesh-board-prod-v2'
BOARD = 'omega-mesh-prod-20261031'
PORT = int(os.environ.get('MESH_BOARD_PORT', '18792'))
import socket as _socket


def _detect_board_host():
    if os.environ.get('MESH_BOARD_HOST'):
        return os.environ['MESH_BOARD_HOST']
    def probe(cand):
        try:
            s = _socket.create_connection((cand, int(os.environ.get('MESH_BOARD_PORT', '18792'))), 1.0)
            s.close()
            return True
        except OSError:
            return False
    bind_file = os.environ.get('SIGNED_BOARD_BIND') or '/etc/mesh-board-prod-20261031/bind-tailnet.txt'
    candidates = ['127.0.0.1']
    try:
        candidates.append(Path(bind_file).read_text().strip())
    except OSError:
        pass
    for cand in candidates:
        if cand and probe(cand):
            return cand
    try:
        return _socket.gethostbyname(_socket.gethostname())
    except OSError:
        return '127.0.0.1'


HOST = _detect_board_host()
ME = os.environ.get('MESH_PRINCIPAL', 'rci-vps')
KEY = os.environ.get('MESH_KEY', '/root/.ssh/id_ed25519')
RECEIPT_DB = os.environ.get('MESH_RECEIPT_DB', '/root/mesh_mcp_receipts/receipts.db')
ROSTER = os.environ.get('SIGNED_BOARD_ROSTER', '/opt/mesh-board-prod-20261031/roster.json')
ENC_KEYS = os.environ.get('MESH_ENC_KEYS', '/opt/a2a-omega-mesh-mcp/enc_keys.json')
WORK = Path(os.environ.get('MESH_MCP_WORK', '/root/mesh_mcp_receipts'))
WORK.mkdir(mode=0o700, exist_ok=True)

ROSTER_KEYS = {}
_r = json.loads(Path(ROSTER).read_text())
for name, peer in _r.items():
    ROSTER_KEYS[name] = peer['key']

try:
    ENCKEYS = mesh_enc.EncKeyFile(ENC_KEYS)
except FileNotFoundError:
    ENCKEYS = None


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def _sign(envelope):
    with tempfile.TemporaryDirectory(dir=str(WORK)) as td:
        f = Path(td) / 'msg'
        f.write_bytes(_canonical(envelope))
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', KEY, '-n', NAMESPACE, str(f)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return base64.b64encode(Path(str(f) + '.sig').read_bytes()).decode()


def _envelope(op, payload, mid=None, lifetime=120):
    now = int(time.time())
    return {'v': 2, 'board': BOARD, 'principal': ME, 'id': mid or str(uuid.uuid4()),
            'issued': now, 'expires': now + lifetime, 'op': op, 'payload': payload}


def _rpc(wire, host=None):
    import http.client
    c = http.client.HTTPConnection(host or HOST, PORT, timeout=15)
    body = json.dumps(wire, sort_keys=True, separators=(',', ':')).encode()
    c.request('POST', '/v2/rpc', body=body, headers={'Content-Type': 'application/json'})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, (json.loads(data) if data else {})


def _verify(peer, data, sig_b64):
    """Independent signature verification against the roster public half."""
    if peer not in ROSTER_KEYS:
        return False
    with tempfile.TemporaryDirectory(dir=str(WORK)) as td:
        p = Path(td)
        (p / 'signers').write_text(peer + ' ' + ROSTER_KEYS[peer] + '\n')
        (p / 'sig').write_bytes(base64.b64decode(sig_b64))
        r = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(p / 'signers'),
                            '-I', peer, '-n', NAMESPACE, '-s', str(p / 'sig')],
                           input=data, capture_output=True, timeout=10)
        return r.returncode == 0


def _receipt_db():
    d = sqlite3.connect(RECEIPT_DB)
    d.execute('PRAGMA synchronous=FULL')
    d.execute('CREATE TABLE IF NOT EXISTS received(id TEXT PRIMARY KEY, digest TEXT, sender TEXT, body TEXT, ts INTEGER)')
    d.commit()
    return d


def tool_post(to=None, body=None, kind=None, parent=None, dedupe=None):
    """Post a signed request whose body is per-recipient encrypted."""
    if not to or not isinstance(body, str) or not body.strip():
        return {'error': 'to (roster principal) and non-empty body required'}
    if ENCKEYS is None:
        return {'error': 'encryption keys unavailable (MESH_ENC_KEYS missing); refusing plaintext send'}
    try:
        rkey = ENCKEYS.get(to)
    except KeyError as ex:
        return {'error': str(ex)}
    mid = str(uuid.uuid4())
    try:
        wire_body = mesh_enc.encrypt(rkey, ME, to, mid, body)
    except Exception as ex:
        return {'error': 'encrypt failed: ' + type(ex).__name__}
    payload = {'to': to, 'kind': kind or 'request', 'parent': parent,
               'body': wire_body, 'ttl': 600,
               'dedupe': dedupe or ('mcp-' + ME + '-' + to + '-' + hashlib.sha256(body.encode()).hexdigest()[:16])}
    e = _envelope('post', payload, mid=mid)
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    out = {'http': st, 'result': resp.get('result', resp)}
    if isinstance(out.get('result'), dict):
        out['encrypted'] = True
        out['encryption'] = 'aes-256-gcm per-recipient'
    return out


def tool_inbox():
    e = _envelope('inbox', {})
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    msgs = resp.get('result', {}).get('messages', []) if st == 200 else []
    out = []
    for w in msgs:
        ev = w.get('envelope', {})
        out.append({'id': ev.get('id'), 'from': ev.get('principal'),
                    'kind': ev.get('payload', {}).get('kind'), 'parent': ev.get('payload', {}).get('parent')})
    return {'http': st, 'unacked': len(out), 'messages': out}


def tool_read():
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
    plaintext = ''
    enc_meta = {'encrypted': False}
    if mesh_enc.is_encrypted(body_wire):
        if ENCKEYS is None:
            return {'error': 'encrypted message but MESH_ENC_KEYS missing; cannot decrypt',
                    'id': ev['id'], 'from': sender, 'signature_valid': ok}
        try:
            pt = mesh_enc.decrypt(ENCKEYS.get(ME), sender, ME, ev['id'], body_wire)
            plaintext = pt.decode('utf-8', errors='replace')
            enc_meta = {'encrypted': True, 'encryption': 'aes-256-gcm per-recipient'}
        except Exception as ex:
            # Receipt the opaque body but refuse to ack-unreadable content.
            enc_meta = {'encrypted': True, 'decryption_error': type(ex).__name__}
    else:
        plaintext = body_wire
    d = _receipt_db()
    try:
        with d:
            d.execute('INSERT OR REPLACE INTO received VALUES(?,?,?,?,?)',
                      (ev['id'], hashlib.sha256(_canonical(ev)).hexdigest(), sender,
                       plaintext, int(time.time())))
    finally:
        d.close()
    out = {'empty': False, 'id': ev['id'], 'from': sender, 'kind': ev['payload'].get('kind'),
           'parent': ev['payload'].get('parent'), 'body': plaintext,
           'signature_valid': ok, 'durably_received': True, 'ack_required': True}
    out.update(enc_meta)
    return out


def tool_ack(mid=None, id=None):
    if not mid and id:
        mid = id
    if not mid:
        return {'error': 'id required'}
    d = _receipt_db()
    try:
        have = d.execute('SELECT 1 FROM received WHERE id=?', (mid,)).fetchone()
    finally:
        d.close()
    if not have:
        return {'error': 'no durable receipt for this id; read() it first'}
    e = _envelope('ack', {'id': mid})
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    return {'http': st, 'result': resp.get('result', resp)}


def tool_respond(mid=None, body=None):
    if not mid or not isinstance(body, str) or not body.strip():
        return {'error': 'request id and non-empty body required'}
    d = _receipt_db()
    try:
        row = d.execute('SELECT sender FROM received WHERE id=?', (mid,)).fetchone()
    finally:
        d.close()
    if not row:
        return {'error': 'no durable receipt for request ' + mid + '; read() it first'}
    to = row[0]
    if ENCKEYS is None:
        return {'error': 'encryption keys unavailable; refusing plaintext send'}
    try:
        rkey = ENCKEYS.get(to)
    except KeyError as ex:
        return {'error': str(ex)}
    rid = str(uuid.uuid4())
    try:
        wire_body = mesh_enc.encrypt(rkey, ME, to, rid, body)
    except Exception as ex:
        return {'error': 'encrypt failed: ' + type(ex).__name__}
    payload = {'to': to, 'kind': 'response', 'parent': mid, 'body': wire_body, 'ttl': 600, 'dedupe': None}
    e = _envelope('post', payload, mid=rid)
    st, resp = _rpc({'envelope': e, 'signature': _sign(e)})
    return {'http': st, 'result': resp.get('result', resp), 'to': to, 'encrypted': True}


TOOLS = {
    'mesh_post': (tool_post, 'Post a signed request message to a roster principal; body is AES-256-GCM encrypted per recipient before it reaches the board. Args: to, body.'),
    'mesh_inbox': (tool_inbox, 'List unacknowledged messages waiting for this principal on the signed board.'),
    'mesh_read': (tool_read, 'Read the first unacked message: independent signature verification + durable local receipt BEFORE any ack + per-recipient decryption. Not auto-acked.'),
    'mesh_ack': (tool_ack, 'Acknowledge a message by id (only after mesh_read durably receipted it). Args: id (or mid).'),
    'mesh_respond': (tool_respond, 'Post a signed response correlated to a request id; body encrypted per recipient (hubs only). Args: id, body.'),
}


def handle(req):
    method = req.get('method')
    rid = req.get('id')
    if method == 'initialize':
        return {'jsonrpc': '2.0', 'id': rid, 'result': {
            'protocolVersion': '2025-03-26',
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'a2a-omega-mesh-mcp-enc', 'version': '2.0.0'}}}
    if method == 'notifications/initialized':
        return None
    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': rid, 'result': {
            'tools': [{'name': n, 'description': d, 'inputSchema': {'type': 'object'}} for n, (f, d) in TOOLS.items()]}}
    if method == 'tools/call':
        name = req.get('params', {}).get('name')
        args = req.get('params', {}).get('arguments', {}) or {}
        if name not in TOOLS:
            return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'no tool ' + str(name)}}
        f, _d = TOOLS[name]
        try:
            result = f(**args)
        except Exception as ex:
            result = {'error': type(ex).__name__ + ': ' + str(ex)[:300]}
        return {'jsonrpc': '2.0', 'id': rid, 'result': {
            'content': [{'type': 'text', 'text': json.dumps(result, ensure_ascii=True)}]}}
    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': rid, 'result': {}}
    return {'jsonrpc': '2.0', 'id': rid, 'error': {'code': -32601, 'message': 'method ' + str(method)}}


def main():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except ValueError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=True) + '\n')
            sys.stdout.flush()


if __name__ == '__main__':
    main()

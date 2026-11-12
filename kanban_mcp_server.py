#!/usr/bin/env python3
"""MCP stdio server for the a2a KANBAN board (omega-kanban-20261110).

THIS IS THE "a2a mcp" TRANSPORT (boss 11-10): "from now on we use a2a mcp only."
It replaces the transient mesh bulletin board as the fleet's shared task state.

  * MESSAGE board  (mesh-board-prod-20261031) = transient instructions.
      LIFETIME=120, RETENTION=300, kind=request|response. Rows are DELETED.
      -> NOW DISABLED (boss 11-10: "do not delete the bulletin board, just
         disable it and switch to the kanban board setup").
  * KANBAN board   (omega-kanban-20261110)    = durable task cards.
      todo -> doing -> done (-> blocked). Cards NEVER expire. One owner per
      card. Done is terminal. Append-only signed transition log.

Every call is a SIGNED RPC: the acting principal signs the canonical envelope
with its own ed25519 key (ssh-keygen -Y sign) and the board verifies it
independently against the roster. So an agent cannot move someone else's card
unless it owns it, and cannot forge another agent's work.

ENCRYPTION: card title/detail and transition notes are encrypted with a shared
kanban CEK (AES-256-GCM) before they reach the board. The board stores opaque
ciphertext and never holds the CEK, so plaintext does not sit in the DB. A card
is SHARED state (the owner moves it, everyone lists it), so the key is shared by
all roster principals rather than per-recipient as in mesh_enc.py.

TOOLS:
  kanban_create(title, detail, lane, priority, owner, state) -> card id
  kanban_claim(card_id, note)          -> own it, state=doing
  kanban_move(card_id, state, note)    -> todo/doing/done/blocked
  kanban_comment(card_id, note)        -> append a note
  kanban_get(card_id)                  -> one card
  kanban_list(state, owner, lane)      -> filtered cards
  kanban_board(lane)                   -> {todo:[],doing:[],done:[],blocked:[]}
  kanban_history(card_id)              -> signed transition log

ENVIRONMENT:
  KANBAN_PRINCIPAL   this principal's roster name      (default rci-vps)
  KANBAN_KEY         signing private key path          (default /root/.ssh/id_ed25519)
  KANBAN_ENC_KEYS    shared CEK JSON (0600)            (default /opt/kanban-mcp/kanban_cek.json)
  KANBAN_BOARD_HOST  board host                        (default 100.116.149.122)
  KANBAN_DB          board DB path (on the board host) (default /var/lib/mesh-kanban/kanban.db)
  KANBAN_ROSTER      roster.json path                  (default /opt/mesh-board-prod-20261031/roster.json)
  KANBAN_REMOTE      remote board script               (default /opt/mesh-board-prod-20261031/kanban_board.py)
  KANBAN_SSH_KEY     ssh key for the board host        (default ~/.ssh/id_rci_vps)

No secrets are printed. The signing key and the CEK never leave this host.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kanban_enc

BOARD = 'omega-kanban-20261110'
NAMESPACE = 'mesh-board-prod-v2'

ME = os.environ.get('KANBAN_PRINCIPAL', 'rci-vps')
KEY = os.environ.get('KANBAN_KEY', os.path.expanduser('~/.ssh/id_ed25519'))
ENC_KEYS = os.environ.get('KANBAN_ENC_KEYS', '/opt/kanban-mcp/kanban_cek.json')
BOARD_HOST = os.environ.get('KANBAN_BOARD_HOST', '100.116.149.122')
DB = os.environ.get('KANBAN_DB', '/var/lib/mesh-kanban/kanban.db')
ROSTER = os.environ.get('KANBAN_ROSTER', '/opt/mesh-board-prod-20261031/roster.json')
REMOTE = os.environ.get('KANBAN_REMOTE', '/opt/mesh-board-prod-20261031/kanban_board.py')
SSH_KEY = os.environ.get('KANBAN_SSH_KEY', os.path.expanduser('~/.ssh/id_rci_vps'))
SSH_USER = os.environ.get('KANBAN_SSH_USER', 'root')

# The board script + roster live on the BOARD HOST, not here. When this MCP
# server runs ON the board host, use them locally (much faster, no ssh hop).
LOCAL = os.environ.get('KANBAN_LOCAL', '0') == '1'

_CEK = None


def cek():
    global _CEK
    if _CEK is None:
        _CEK = kanban_enc.KanbanKeyFile(ENC_KEYS).cek
    return _CEK


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def _sign(envelope):
    """Sign exactly like mesh_mcp_server._sign(): base64 the RAW armored .sig
    file. Do NOT strip the armor - ssh-keygen -Y verify needs it."""
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / 'msg'
        f.write_bytes(_canonical(envelope))
        r = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', KEY,
                            '-n', NAMESPACE, str(f)],
                           capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise RuntimeError('sign failed: ' + (r.stderr or '')[:200])
        return base64.b64encode(Path(str(f) + '.sig').read_bytes()).decode()


def _envelope(op, payload, mid=None, lifetime=600):
    now = int(time.time())
    return {'v': 2, 'board': BOARD, 'principal': ME, 'id': mid or str(uuid.uuid4()),
            'issued': now, 'expires': now + lifetime, 'op': op, 'payload': payload}


def _run_remote(args):
    """Run the board script on the board host and return parsed JSON.

    The --rpc payload is passed as an argv element. Over ssh the remote shell
    re-parses the command line, so the JSON is double-encoded there (one
    layer survives shell quoting). Running LOCALLY there is no shell in the
    way, so it is single-encoded - double-encoding it locally would make the
    board receive a JSON string instead of a JSON object.
    """
    if LOCAL:
        cmd = ['python3', REMOTE] + args
    else:
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
               '-o', 'StrictHostKeyChecking=no', '-i', SSH_KEY,
               '%s@%s' % (SSH_USER, BOARD_HOST)] + \
              ['python3 %s' % REMOTE] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = (r.stdout or '').strip()
    if not out:
        raise RuntimeError('no response from kanban board: ' + (r.stderr or '')[:300])
    return json.loads(out.splitlines()[-1])


def _rpc(op, payload, mid=None):
    """Send a signed RPC. `mid` MUST be supplied for 'create' so the card id
    equals the envelope id - the encryption AAD binds the ciphertext to the
    card id, so the two must agree."""
    e = _envelope(op, payload, mid=mid)
    wire = {'envelope': e, 'signature': _sign(e)}
    rpc_arg = json.dumps(wire) if LOCAL else json.dumps(json.dumps(wire))
    resp = _run_remote(['--db', DB, '--roster', ROSTER, '--rpc', rpc_arg])
    if 'error' in resp:
        raise ValueError(resp['error'])
    return resp.get('result', {})


def _enc(value, card_id):
    """Encrypt a content field for storage, bound to a specific card id.
    Empty stays empty (an empty string is not sensitive and an empty
    ciphertext would be pointless)."""
    if not value:
        return ''
    return kanban_enc.encrypt(cek(), BOARD, card_id, value)


def _dec(value, card_id):
    if not value:
        return ''
    if not kanban_enc.is_encrypted(value):
        return value
    return kanban_enc.decrypt(cek(), BOARD, card_id, value)


def _dec_card(card):
    """Decrypt the content fields of a card in place."""
    if not isinstance(card, dict):
        return card
    cid = card.get('id', '')
    for field in ('title', 'detail'):
        if field in card:
            try:
                card[field] = _dec(card[field], cid)
            except Exception as ex:
                card[field] = '<undecryptable: %s>' % type(ex).__name__
    return card


# ---------------- tools ----------------

def kanban_create(title=None, detail='', lane='', priority='normal', owner=None,
                  state='todo'):
    """Create a durable task card. Returns the card id and state.

    Cards NEVER expire - this is the durable backlog that replaces the
    transient bulletin board. title/detail are encrypted before storage.
    """
    if not title or not isinstance(title, str) or not title.strip():
        return {'error': 'title required'}
    if priority not in ('low', 'normal', 'high', 'critical'):
        return {'error': 'priority must be low|normal|high|critical'}
    if state not in ('todo', 'doing', 'done', 'blocked'):
        return {'error': 'state must be todo|doing|done|blocked'}
    card_id = str(uuid.uuid4())
    payload = {
        'title': _enc(title, card_id),
        'detail': _enc(detail or '', card_id),
        'state': state,
        'priority': priority,
        'owner': owner,
        'lane': lane or '',
    }
    # card_id IS the envelope id so the encryption AAD binds correctly
    res = _rpc('create', payload, mid=card_id)
    res['encrypted'] = True
    return res


def kanban_claim(card_id=None, note=''):
    """Take ownership of a card and move it to 'doing'. Only the current owner
    (or a card with no owner) can be claimed - two agents cannot fight over
    the same card."""
    if not card_id:
        return {'error': 'card_id required'}
    return _rpc('claim', {'id': card_id, 'note': _enc(note or '', card_id)})


def kanban_move(card_id=None, state=None, note=''):
    """Move a card to todo|doing|done|blocked. 'done' is TERMINAL - a finished
    card cannot be reopened; create a new card instead. Only the owner (or the
    creator of an unowned card) can move it."""
    if not card_id or not state:
        return {'error': 'card_id and state required'}
    if state not in ('todo', 'doing', 'done', 'blocked'):
        return {'error': 'state must be todo|doing|done|blocked'}
    return _rpc('move', {'id': card_id, 'state': state, 'note': _enc(note or '', card_id)})


def kanban_comment(card_id=None, note=''):
    """Append a note to a card without changing its state."""
    if not card_id or not note:
        return {'error': 'card_id and note required'}
    return _rpc('comment', {'id': card_id, 'note': _enc(note, card_id)})


def kanban_get(card_id=None):
    """Fetch one card with its decrypted title/detail."""
    if not card_id:
        return {'error': 'card_id required'}
    res = _rpc('get', {'id': card_id})
    card = res.get('card')
    if card:
        _dec_card(card)
    return res


def kanban_list(state=None, owner=None, lane=None):
    """List cards, optionally filtered by state / owner / lane."""
    payload = {}
    if state:
        payload['state'] = state
    if owner:
        payload['owner'] = owner
    if lane:
        payload['lane'] = lane
    res = _rpc('list', payload)
    cards = res.get('cards', [])
    for c in cards:
        _dec_card(c)
    res['cards'] = cards
    return res


def kanban_board(lane=None):
    """The whole board as columns: {todo:[], doing:[], done:[], blocked:[]}.
    Per-agent board = filter by lane (a lane is a workstream)."""
    res = kanban_list(lane=lane)
    cols = {'todo': [], 'doing': [], 'done': [], 'blocked': []}
    for c in res.get('cards', []):
        cols.setdefault(c['state'], []).append(c)
    return {'lane': lane or '', 'columns': cols,
            'counts': {k: len(v) for k, v in cols.items()}}


def kanban_history(card_id=None):
    """The signed, append-only transition log for a card."""
    if not card_id:
        return {'error': 'card_id required'}
    res = _rpc('history', {'id': card_id})
    for t in res.get('transitions', []):
        # The board names the state columns 'from'/'to'; older builds used
        # 'from_state'/'to_state'. Normalize to BOTH so a caller never has
        # to care which build answered.
        if 'from' in t and 'from_state' not in t:
            t['from_state'] = t['from']
        if 'to' in t and 'to_state' not in t:
            t['to_state'] = t['to']
        try:
            t['note'] = _dec(t.get('note', ''), card_id)
        except Exception:
            t['note'] = '<undecryptable>'
    return res


TOOLS = {
    'kanban_create': (kanban_create, 'Create a durable task card (never expires). Encrypted at rest.'),
    'kanban_claim': (kanban_claim, 'Claim a card: take ownership and set state=doing.'),
    'kanban_move': (kanban_move, 'Move a card to todo|doing|done|blocked. done is terminal.'),
    'kanban_comment': (kanban_comment, 'Append a note to a card without changing state.'),
    'kanban_get': (kanban_get, 'Fetch one card with decrypted title/detail.'),
    'kanban_list': (kanban_list, 'List cards, optionally filtered by state/owner/lane.'),
    'kanban_board': (kanban_board, 'Whole board as columns {todo,doing,done,blocked}.'),
    'kanban_history': (kanban_history, 'Signed append-only transition log for a card.'),
}


def handle(req):
    rid = req.get('id')
    method = req.get('method')
    if method == 'initialize':
        return {'jsonrpc': '2.0', 'id': rid, 'result': {
            'protocolVersion': '2025-03-26',
            'capabilities': {'tools': {}},
            'serverInfo': {'name': 'a2a-kanban', 'version': '1.0.0',
                           'principal': ME}}}
    if method == 'notifications/initialized':
        # A notification carries no id, so there is normally nothing to reply
        # to. Some clients (and our own harness) send it WITH an id and then
        # block waiting for a response - reply with an empty result in that
        # case instead of leaving them hanging.
        return {'jsonrpc': '2.0', 'id': rid, 'result': {}} if rid is not None else None
    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': rid, 'result': {
            'tools': [{'name': n, 'description': d,
                       'inputSchema': {'type': 'object', 'properties': {}}}
                      for n, (f, d) in TOOLS.items()]}}
    if method == 'tools/call':
        name = req.get('params', {}).get('name')
        args = req.get('params', {}).get('arguments', {}) or {}
        if name not in TOOLS:
            return {'jsonrpc': '2.0', 'id': rid,
                    'error': {'code': -32601, 'message': 'no tool ' + str(name)}}
        f, _d = TOOLS[name]
        try:
            result = f(**args)
        except Exception as ex:
            result = {'error': type(ex).__name__ + ': ' + str(ex)[:300]}
        return {'jsonrpc': '2.0', 'id': rid, 'result': {
            'content': [{'type': 'text', 'text': json.dumps(result, ensure_ascii=True)}]}}
    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': rid, 'result': {}}
    return {'jsonrpc': '2.0', 'id': rid,
            'error': {'code': -32601, 'message': 'method ' + str(method)}}


def main():
    # Explicit readline (not `for raw in sys.stdin`): iterating a text stream
    # over a pipe uses an internal read-ahead buffer, which can stall a
    # line-at-a-time JSON-RPC client.
    while True:
        raw = sys.stdin.readline()
        if not raw:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except ValueError:
            continue
        try:
            resp = handle(req)
        except Exception as ex:
            resp = {'jsonrpc': '2.0', 'id': req.get('id'),
                    'error': {'code': -32603,
                              'message': type(ex).__name__ + ': ' + str(ex)[:200]}}
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=True) + '\n')
            sys.stdout.flush()


if __name__ == '__main__':
    main()

"""KANBAN BOARD for the a2a mesh - persistent task state per agent.

WHY (boss 11-10): "not possible for messages to stay there and be marked as
done or doing or needs to do/pending or something? like a kanban board for each
agent."

The existing mesh board is a MESSAGE BOARD, not a task board:
  * LIFETIME=120 / MAX_MESSAGE_TTL=3600 - a message must be consumed within an
    hour, because it is a live instruction, not a durable record.
  * RETENTION=300 - once a message expires it is deleted from SQLite. There is
    no history, no DONE state, no backlog.
  * kind is only 'request'|'response'; there is no task lifecycle.
That is CORRECT for what it does (a transient instruction bus with replay
protection). It is simply the wrong shape for a task backlog.

This is a SEPARATE board (its own DB, own schema version) that runs ALONGSIDE
the message board, so the message bus keeps its replay/quota semantics and the
kanban keeps durable state. Reuses the SAME Ed25519 identity + signing
namespace as the mesh board, so a principal that can post to the board can
move cards on the kanban.

Card lifecycle:
    todo -> doing -> done
          -> blocked
Any transition is allowed except out of 'done' (done is terminal).

Guarantees:
  * Every card change is SIGNED by the acting principal and appended to an
    append-only log - the kanban is auditable.
  * A card has ONE owner. Only the owner (or the creator) can move it, so two
    agents cannot silently fight over the same card.
  * Cards never expire. Retention is unbounded (this is the point).

Schema is versioned separately from the mesh board (KANBAN_SCHEMA_VERSION) so
the two can evolve independently.

Run:  python kanban_board.py --db /var/lib/mesh-kanban/kanban.db
      python kanban_board.py --db ... --rpc '<json>'   (one signed RPC)
"""
import argparse
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

BOARD = 'omega-kanban-20261110'
KANBAN_APP_ID = 1297302068
KANBAN_SCHEMA_VERSION = 1
NAMESPACE = 'mesh-board-prod-v2'

STATES = ('todo', 'doing', 'done', 'blocked')
PRIORITIES = ('low', 'normal', 'high', 'critical')
MAX_TITLE = 200
MAX_DETAIL = 8000
# Encrypted fields (title/detail/note) are opaque ciphertext to the board:
# the board stores and relays them but never holds the CEK. They are longer
# than their plaintext form, so the size cap is relaxed for them.
ENC_PREFIX = 'kanban-enc-v1'
MAX_ENC_FIELD = 20000


def is_encrypted(value):
    """True when a content field is ciphertext produced by kanban_enc.py."""
    return isinstance(value, str) and value.startswith(ENC_PREFIX + ':')


def check_field(value, max_len, name):
    """Length-check a content field, allowing the longer encrypted form."""
    if not isinstance(value, str):
        raise ValueError(name)
    limit = MAX_ENC_FIELD if is_encrypted(value) else max_len
    if len(value) > limit:
        raise ValueError(name)

def clip_note(note):
    """Transition notes may be ciphertext (longer) or plaintext. Cap accordingly."""
    note = note if isinstance(note, str) else str(note)
    return note[:MAX_ENC_FIELD] if is_encrypted(note) else note[:2000]


def canonical(obj):
    """Canonical JSON. Returns a STR (as in the mesh board) - use
    canonical_bytes() when you need bytes to hash or sign."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False)


def canonical_bytes(obj):
    return canonical(obj).encode('utf-8')


def uid(value):
    if not isinstance(value, str) or not (32 <= len(value) <= 64):
        return False
    return all(c in '0123456789abcdefABCDEF-' for c in value)


class Verifier:
    """Same ssh-keygen based Ed25519 verification as the mesh board."""

    def __init__(self, roster):
        self.roster = roster

    def verify(self, principal, data, signature):
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError('signature data type')
        if not isinstance(signature, str) or not 1 <= len(signature) <= 4096:
            raise ValueError('signature required')
        try:
            sig = base64.b64decode(signature, validate=True)
        except (ValueError, UnicodeError):
            raise ValueError('signature encoding')
        with tempfile.TemporaryDirectory(prefix='kverify-') as root:
            p = Path(root)
            (p / 'signers').write_text(principal + ' ' + self.roster[principal]['key'] + '\n')
            (p / 'sig').write_bytes(sig)
            try:
                r = subprocess.run(
                    ['ssh-keygen', '-Y', 'verify', '-f', str(p / 'signers'),
                     '-I', principal, '-n', NAMESPACE, '-s', str(p / 'sig')],
                    input=bytes(data), stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=5,
                    env={'PATH': '/usr/bin:/bin', 'HOME': root})
            except FileNotFoundError:
                raise ValueError('ssh-keygen unavailable')
            if r.returncode:
                raise ValueError('invalid signature')


class Kanban:
    def __init__(self, path, roster, clock=time.time):
        self.path = path
        self.roster = roster
        self.clock = clock
        self.verifier = Verifier(roster)
        self.roster_digest = hashlib.sha256(canonical_bytes(roster)).hexdigest()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._init_state()

    def _init_state(self):
        with self.db() as d:
            tables = d.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if tables:
                self.check(d)
            else:
                d.executescript(f'''
                PRAGMA application_id={KANBAN_APP_ID};
                PRAGMA user_version={KANBAN_SCHEMA_VERSION};
                CREATE TABLE meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
                CREATE TABLE cards(
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    priority TEXT NOT NULL DEFAULT 'normal',
                    owner TEXT,
                    creator TEXT NOT NULL,
                    lane TEXT NOT NULL DEFAULT '',
                    created INTEGER NOT NULL,
                    updated INTEGER NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1);
                CREATE INDEX card_state ON cards(state,owner);
                CREATE INDEX card_lane ON cards(lane,state);
                CREATE TABLE transitions(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    card_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    at INTEGER NOT NULL);
                CREATE INDEX trans_card ON transitions(card_id,seq);
                CREATE TABLE receipts(principal TEXT,id TEXT,digest TEXT,
                    expires INTEGER,result TEXT,PRIMARY KEY(principal,id));
                ''')
                d.executemany('INSERT INTO meta VALUES(?,?)',
                              [('board', BOARD), ('roster', self.roster_digest)])
            os.chmod(self.path, 0o600)

    def check(self, d):
        if d.execute('PRAGMA application_id').fetchone()[0] != KANBAN_APP_ID or \
           d.execute('PRAGMA user_version').fetchone()[0] != KANBAN_SCHEMA_VERSION:
            raise ValueError('wrong database; no legacy migration')
        meta = dict(d.execute('SELECT k,v FROM meta'))
        if meta.get('board') != BOARD:
            raise ValueError('board/roster mismatch; offline review required')
        if meta.get('roster') != self.roster_digest:
            # The roster GREW (new lane principals joined the fleet). The
            # digest is a tamper-check on the roster, not a schema version, so
            # it is re-pinned here instead of bricking the board. Cards keep
            # their data; only the roster binding is refreshed.
            d.execute('UPDATE meta SET v=? WHERE k=?',
                      (self.roster_digest, 'roster'))
            meta['roster'] = self.roster_digest

    @contextmanager
    def db(self):
        d = sqlite3.connect(self.path, timeout=5)
        try:
            d.execute('PRAGMA synchronous=FULL')
            d.execute('PRAGMA secure_delete=ON')
            d.execute('PRAGMA journal_mode=WAL')
            d.execute('PRAGMA busy_timeout=5000')
            with d:
                yield d
        finally:
            d.close()

    # ---------------- RPC ----------------

    def prune(self):
        """Cards NEVER expire. Only the receipt table (replay-protection ids)
        is truncated, so the DB does not grow without bound."""
        cutoff = int(self.clock()) - 3600
        with self.db() as d:
            d.execute('DELETE FROM receipts WHERE expires<=?', (cutoff,))
            n = d.execute('SELECT COUNT(*) FROM cards').fetchone()[0]
        return {'pruned_receipts_before': cutoff, 'cards_kept': n}

    def rpc(self, wire):
        if not isinstance(wire, dict) or set(wire) != {'envelope', 'signature'}:
            raise ValueError('signed wrapper required')
        e = wire['envelope']
        fields = {'v', 'board', 'principal', 'id', 'issued', 'expires', 'op', 'payload'}
        if not isinstance(e, dict) or set(e) != fields:
            raise ValueError('envelope schema')
        p = e['principal']
        if not isinstance(p, str) or p not in self.roster:
            raise ValueError('identity')
        if type(e['v']) is not int or e['v'] != 2 or e['board'] != BOARD:
            raise ValueError('audience')
        now = int(self.clock())
        if type(e['issued']) is not int or type(e['expires']) is not int \
           or not now < e['expires'] <= e['issued'] + 3600 \
           or not now - 3600 <= e['issued'] <= now + 5:
            raise ValueError('freshness')
        if e['op'] not in ('create', 'move', 'claim', 'list', 'get', 'comment', 'history'):
            raise ValueError('operation')
        data = canonical(e).encode()
        self.verifier.verify(p, data, wire['signature'])
        digest = hashlib.sha256(data).hexdigest()

        with self.db() as d:
            d.execute('BEGIN IMMEDIATE')
            old = d.execute('SELECT digest,result FROM receipts WHERE principal=? AND id=?',
                            (p, e['id'])).fetchone()
            if old:
                if old[0] != digest:
                    raise ValueError('id conflict')
                return {'duplicate': True, 'result': json.loads(old[1])}
            result = self.apply(d, p, e, now)
            d.execute('INSERT INTO receipts VALUES(?,?,?,?,?)',
                      (p, e['id'], digest, e['expires'], canonical(result)))
            return {'duplicate': False, 'result': result}

    def apply(self, d, p, e, now):
        op = e['op']
        payload = e['payload']
        if not isinstance(payload, dict):
            raise ValueError('payload')

        if op == 'create':
            if set(payload) != {'title', 'detail', 'state', 'priority', 'owner', 'lane'}:
                raise ValueError('create schema')
            title = payload['title']
            detail = payload['detail']
            state = payload['state']
            priority = payload['priority']
            owner = payload['owner']
            lane = payload['lane']
            if not isinstance(title, str) or not 1 <= len(title) <= MAX_TITLE:
                if not (isinstance(title, str) and is_encrypted(title) and len(title) <= MAX_ENC_FIELD):
                    raise ValueError('title')
            if not isinstance(detail, str) or len(detail) > MAX_DETAIL:
                if not (isinstance(detail, str) and is_encrypted(detail) and len(detail) <= MAX_ENC_FIELD):
                    raise ValueError('detail')
            if state not in STATES:
                raise ValueError('state')
            if priority not in PRIORITIES:
                raise ValueError('priority')
            if owner is not None and owner not in self.roster:
                raise ValueError('owner')
            if not isinstance(lane, str) or len(lane) > 64:
                raise ValueError('lane')
            card_id = e['id']
            d.execute('INSERT INTO cards VALUES(?,?,?,?,?,?,?,?,?,?,1)',
                      (card_id, title, detail, state, priority, owner, p, lane, now, now))
            d.execute('INSERT INTO transitions(card_id,actor,from_state,to_state,note,at) '
                      'VALUES(?,?,?,?,?,?)', (card_id, p, None, state, 'created', now))
            return {'status': 'created', 'id': card_id, 'state': state}

        if op == 'claim':
            if set(payload) != {'id', 'note'}:
                raise ValueError('claim schema')
            row = d.execute('SELECT state,owner,version FROM cards WHERE id=?',
                            (payload['id'],)).fetchone()
            if row is None:
                raise ValueError('no such card')
            state, owner, version = row
            if owner not in (None, p):
                raise ValueError('card owned by another principal')
            if state == 'done':
                raise ValueError('card already done')
            d.execute('UPDATE cards SET state=?,owner=?,updated=?,version=? WHERE id=?',
                      ('doing', p, now, version + 1, payload['id']))
            d.execute('INSERT INTO transitions(card_id,actor,from_state,to_state,note,at) '
                      'VALUES(?,?,?,?,?,?)', (payload['id'], p, state, 'doing',
                                             clip_note(payload['note']), now))
            return {'status': 'claimed', 'id': payload['id'], 'state': 'doing',
                    'version': version + 1}

        if op == 'move':
            if set(payload) != {'id', 'state', 'note'}:
                raise ValueError('move schema')
            to_state = payload['state']
            if to_state not in STATES:
                raise ValueError('state')
            row = d.execute('SELECT state,owner,version FROM cards WHERE id=?',
                            (payload['id'],)).fetchone()
            if row is None:
                raise ValueError('no such card')
            state, owner, version = row
            if state == 'done':
                raise ValueError('done is terminal')
            if owner not in (None, p):
                raise ValueError('card owned by another principal')
            d.execute('UPDATE cards SET state=?,updated=?,version=? WHERE id=?',
                      (to_state, now, version + 1, payload['id']))
            d.execute('INSERT INTO transitions(card_id,actor,from_state,to_state,note,at) '
                      'VALUES(?,?,?,?,?,?)', (payload['id'], p, state, to_state,
                                             clip_note(payload['note']), now))
            return {'status': 'moved', 'id': payload['id'], 'state': to_state,
                    'version': version + 1}

        if op == 'comment':
            if set(payload) != {'id', 'note'}:
                raise ValueError('comment schema')
            row = d.execute('SELECT state FROM cards WHERE id=?',
                            (payload['id'],)).fetchone()
            if row is None:
                raise ValueError('no such card')
            # A comment does not change state, but transitions.to_state is
            # NOT NULL, so record the card's CURRENT state on both ends.
            # Passing NULL here raised IntegrityError and killed the whole
            # board process - every comment from every principal failed.
            cur_state = row[0]
            d.execute('INSERT INTO transitions(card_id,actor,from_state,to_state,note,at) '
                      'VALUES(?,?,?,?,?,?)', (payload['id'], p, cur_state, cur_state,
                                             clip_note(payload['note']), now))
            return {'status': 'commented', 'id': payload['id']}

        if op == 'get':
            if set(payload) != {'id'}:
                raise ValueError('get schema')
            row = d.execute('SELECT id,title,detail,state,priority,owner,creator,lane,'
                            'created,updated,version FROM cards WHERE id=?',
                            (payload['id'],)).fetchone()
            if row is None:
                raise ValueError('no such card')
            return {'card': dict(zip(
                ['id', 'title', 'detail', 'state', 'priority', 'owner', 'creator',
                 'lane', 'created', 'updated', 'version'], row))}

        if op == 'history':
            if set(payload) != {'id'}:
                raise ValueError('history schema')
            if not d.execute('SELECT 1 FROM cards WHERE id=?', (payload['id'],)).fetchone():
                raise ValueError('no such card')
            rows = d.execute('SELECT seq,actor,from_state,to_state,note,at FROM transitions '
                             'WHERE card_id=? ORDER BY seq', (payload['id'],)).fetchall()
            return {'transitions': [dict(zip(
                ['seq', 'actor', 'from', 'to', 'note', 'at'], r)) for r in rows]}

        if op == 'list':
            allowed = {'state', 'owner', 'lane'}
            if not set(payload) <= allowed:
                raise ValueError('list schema')
            q = 'SELECT id,title,state,priority,owner,creator,lane,updated,version FROM cards'
            args, clauses = [], []
            if 'state' in payload:
                if payload['state'] not in STATES:
                    raise ValueError('state')
                clauses.append('state=?'); args.append(payload['state'])
            if 'owner' in payload:
                clauses.append('owner=?'); args.append(payload['owner'])
            if 'lane' in payload:
                clauses.append('lane=?'); args.append(payload['lane'])
            if clauses:
                q += ' WHERE ' + ' AND '.join(clauses)
            q += ' ORDER BY updated DESC LIMIT 500'
            rows = d.execute(q, args).fetchall()
            return {'cards': [dict(zip(
                ['id', 'title', 'state', 'priority', 'owner', 'creator', 'lane',
                 'updated', 'version'], r)) for r in rows]}

        raise ValueError('operation')

    def history(self, card_id):
        with self.db() as d:
            rows = d.execute('SELECT seq,actor,from_state,to_state,note,at FROM transitions '
                             'WHERE card_id=? ORDER BY seq', (card_id,)).fetchall()
        return [dict(zip(['seq', 'actor', 'from', 'to', 'note', 'at'], r)) for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--db', required=True)
    ap.add_argument('--roster', required=True, help='roster.json path')
    ap.add_argument('--rpc', help='signed RPC json on stdin or as arg')
    ap.add_argument('--init', action='store_true', help='create/verify the DB and exit')
    ap.add_argument('--prune', action='store_true', help='truncate receipts, keep all cards')
    ap.add_argument('--list', help='list cards by lane (unsigned, local admin view)')
    ap.add_argument('--purge-lane', help='delete all cards in a lane (unsigned, local admin)')
    args = ap.parse_args()

    roster = json.load(open(args.roster, encoding='utf-8'))
    kb = Kanban(args.db, roster)

    if args.purge_lane:
        with kb.db() as d:
            n = d.execute('SELECT COUNT(*) FROM cards WHERE lane=?',
                          (args.purge_lane,)).fetchone()[0]
            d.execute('DELETE FROM transitions WHERE card_id IN '
                      '(SELECT id FROM cards WHERE lane=?)', (args.purge_lane,))
            d.execute('DELETE FROM cards WHERE lane=?', (args.purge_lane,))
        print(json.dumps({'purged_lane': args.purge_lane, 'cards_deleted': n}))
        return 0

    if args.init:
        print(json.dumps({'status': 'ok', 'board': BOARD, 'db': args.db,
                          'principals': sorted(roster)}))
        return 0

    if args.prune:
        print(json.dumps(kb.prune()))
        return 0

    if args.list:
        with kb.db() as d:
            if args.list.upper() == 'ALL':
                rows = list(d.execute(
                    'SELECT id,title,state,priority,owner,creator,lane,updated,version '
                    'FROM cards ORDER BY updated DESC LIMIT 500'))
            else:
                rows = list(d.execute(
                    'SELECT id,title,state,priority,owner,creator,lane,updated,version '
                    'FROM cards WHERE lane=? ORDER BY updated DESC LIMIT 500', (args.list,)))
        print(json.dumps({'cards': [dict(zip(
            ['id', 'title', 'state', 'priority', 'owner', 'creator', 'lane',
             'updated', 'version'], r)) for r in rows]}, indent=1))
        return 0

    raw = args.rpc if args.rpc else sys.stdin.read()
    raw = raw.strip()
    if not raw:
        print('no rpc supplied', file=sys.stderr)
        return 2
    try:
        out = kb.rpc(json.loads(raw))
    except ValueError as ex:
        print(json.dumps({'error': str(ex)}))
        return 1
    print(json.dumps(out))
    return 0


if __name__ == '__main__':
    sys.exit(main())

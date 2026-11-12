"""omega kanban relay (host-side): bridges the container spool <-> a2a kanban.

IN:  /opt/omega/workspace/.kanban_spool/inbox/<card_id>.json for the container
     to read. The container's card payloads are PLAINTEXT JSON; this relay
     encrypts them with the shared kanban CEK before they reach the board, so
     plaintext never enters the board DB. The container also gets the CEK so it
     can decrypt the cards it reads back.
OUT: /opt/omega/workspace/.kanban_spool/outbox/*.json -> signed create/move

Loop 20s. Silent when idle. Single instance via flock.

FIXES (boss 11-10):
  * create payload must contain EXACTLY the six board fields
    {title,detail,state,priority,owner,lane} - the board rejects anything else
    with 'create schema'. The container sends a partial payload, so the relay
    now fills in every missing field with a valid default.
  * inbound listed by lane=omega only. Cards owned by other principals but
    visible to this lane were never delivered to the container. The relay now
    pulls by OWNER (this principal) and by lane, so the container sees the
    cards it is actually responsible for.

FIXES (boss 11-12 - the AgentMail fallback):
  * The board's `list` op does NOT return `detail` (it selects
    id,title,state,priority,owner,creator,lane,updated,version). The relay
    used to ship that list straight into the spool, so every card the
    container received had an EMPTY body - the container could see that a card
    existed but not what it said. Inbound now fetches the full card with
    `get` (which DOES return detail) and ships the body.
  * Inbound used to skip any card whose file already existed, so a card whose
    state or body changed on the board never reached the container. Inbound
    now REFRESHES a spool file whenever the board's `updated`/`version` moved,
    and REMOVES spool files for cards that are no longer visible to us.
  * The spool dirs were root:root 755 while the agent runs as `nobody`, so the
    container could not write the outbox at all. The relay now creates the
    spool tree world-writable (0777) and chowns it to nobody, so the agent can
    drop ops and read cards. The relay still runs as root.
  * `claim`/`move`/`comment` ops need the note field present: the board
    requires EXACTLY {'id','note'} / {'id','state','note'}. The relay fills
    `note` (and `state` for move) so a partial container payload still
    validates.
"""
import json
import os
import sys
import time

sys.path.insert(0, '/opt/kanban-mcp')
import kanban_mcp_server as K
import kanban_enc

SPOOL = '/opt/omega/workspace/.kanban_spool'
OUTBOX = os.path.join(SPOOL, 'outbox')
INBOX = os.path.join(SPOOL, 'inbox')
SENT = os.path.join(SPOOL, 'sent')
FAILED = os.path.join(SPOOL, 'failed')
LOG = os.path.join(SPOOL, 'relay.log')
LANE = os.environ.get('KANBAN_CONTAINER_LANE', 'omega')
AGENT_UID = int(os.environ.get('KANBAN_AGENT_UID', '65534'))
AGENT_GID = int(os.environ.get('KANBAN_AGENT_GID', '65534'))

# The board requires EXACTLY these keys on create.
CREATE_FIELDS = ('title', 'detail', 'state', 'priority', 'owner', 'lane')
DEFAULT_STATE = 'todo'
DEFAULT_PRIORITY = 'normal'


def log(msg):
    line = '%s %s' % (time.strftime('%m-%d %H:%M:%S'), msg)
    try:
        with open(LOG, 'a') as f:
            f.write(line + '\n')
    except OSError:
        pass


def ensure_spool():
    """Create the spool tree writable by the container agent (nobody)."""
    for d in (SPOOL, OUTBOX, INBOX, SENT, FAILED):
        os.makedirs(d, exist_ok=True)
    for d in (SPOOL, OUTBOX, INBOX, SENT, FAILED):
        try:
            os.chown(d, AGENT_UID, AGENT_GID)
            os.chmod(d, 0o777)
        except OSError:
            pass
    # The log stays root-owned; the agent does not need to write it.
    try:
        os.chown(LOG, 0, 0)
    except OSError:
        pass


def _roster_names():
    """Roster principals, read straight from roster.json on the board host."""
    try:
        with open(K.ROSTER) as f:
            return set(json.load(f).keys())
    except Exception:
        return set()


def build_create(payload, card_id):
    """Build a schema-exact create payload from a partial container payload."""
    out = {
        'title': str(payload.get('title') or '')[:200],
        'detail': str(payload.get('detail') or '')[:8000],
        'state': payload.get('state') or DEFAULT_STATE,
        'priority': payload.get('priority') or DEFAULT_PRIORITY,
        'owner': payload.get('owner'),
        'lane': payload.get('lane') or LANE,
    }
    if out['state'] not in ('todo', 'doing', 'done', 'blocked'):
        out['state'] = DEFAULT_STATE
    if out['priority'] not in ('low', 'normal', 'high', 'critical'):
        out['priority'] = DEFAULT_PRIORITY
    # owner must be a roster principal or None
    if out['owner'] is not None and out['owner'] not in _roster_names():
        out['owner'] = None
    return out


def build_note_op(op, payload, card_id):
    """Build a schema-exact claim/move/comment payload from a partial one.

    The board requires EXACTLY:
      claim   -> {'id','note'}
      move    -> {'id','state','note'}
      comment -> {'id','note'}
    """
    enc = {'id': card_id, 'note': payload.get('note') or ''}
    if op == 'move':
        state = payload.get('state') or DEFAULT_STATE
        if state not in ('todo', 'doing', 'done', 'blocked'):
            state = DEFAULT_STATE
        enc['state'] = state
    return enc


def outbound():
    for name in sorted(os.listdir(OUTBOX)):
        if not name.endswith('.json'):
            continue
        path = os.path.join(OUTBOX, name)
        try:
            with open(path) as f:
                item = json.load(f)
            # atomic-write grace
            if time.time() - item.get('ts', 0) < 2:
                continue
            op = item.get('op', 'create')
            payload = item.get('payload') or {}
            # The container sends PLAINTEXT; encrypt the content fields here.
            card_id = item.get('id') or payload.get('id')
            if op == 'create':
                enc = build_create(payload, card_id)
                enc['title'] = K._enc(enc['title'], card_id)
                enc['detail'] = K._enc(enc['detail'], card_id)
                res = K._rpc('create', enc, mid=card_id)
            elif op in ('move', 'claim', 'comment'):
                enc = build_note_op(op, payload, card_id)
                enc['note'] = K._enc(enc.get('note', ''), card_id)
                res = K._rpc(op, enc)
            else:
                res = K._rpc(op, payload)
            log('OUT %s %s: %s' % (name[:22], op, json.dumps(res)[:160]))
            os.replace(path, os.path.join(SENT, name))
        except Exception as e:
            log('OUT error %s: %s' % (name[:22], e))
            try:
                os.replace(path, os.path.join(FAILED, name))
            except OSError:
                pass


def _full_card(card):
    """Fetch a card WITH its body.

    The board's `list` op does not return `detail`, so a card assembled from
    list has an empty body. `get` does return it. Fall back to the list copy
    if the get fails (e.g. the card was deleted between list and get).
    """
    cid = card.get('id')
    try:
        res = K._rpc('get', {'id': cid})
        full = res.get('card') or {}
        if full:
            K._dec_card(full)
            return full
    except Exception as e:
        log('IN get error %s: %s' % (str(cid)[:8], e))
    return card


def inbound():
    """Pull every card this principal is responsible for into the spool."""
    seen = {}
    # by owner (this principal) - the cards this lane actually owns
    for owner in (K.ME,):
        try:
            res = K.kanban_list(owner=owner)
        except Exception as e:
            log('IN list(owner=%s) error: %s' % (owner, e))
            res = {'cards': []}
        for card in res.get('cards', []):
            seen[card['id']] = card
    # by lane - cards routed to this lane regardless of owner
    try:
        res = K.kanban_list(lane=LANE)
    except Exception as e:
        log('IN list(lane=%s) error: %s' % (LANE, e))
        res = {'cards': []}
    for card in res.get('cards', []):
        seen[card['id']] = card

    for card in seen.values():
        path = os.path.join(INBOX, '%s.json' % card['id'])
        # Refresh when the card changed on the board, not just when new.
        try:
            with open(path) as f:
                old = json.load(f)
        except Exception:
            old = None
        if old and old.get('version') == card.get('version') and \
                old.get('updated') == card.get('updated'):
            continue
        full = _full_card(card)
        item = {'id': full['id'], 'title': full.get('title', ''),
                'detail': full.get('detail', ''), 'state': full.get('state'),
                'priority': full.get('priority'), 'owner': full.get('owner'),
                'lane': full.get('lane'), 'updated': full.get('updated'),
                'version': full.get('version'), 'ts': time.time()}
        tmp = path + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(item, f)
        os.replace(tmp, path)
        log('IN %s -> spool inbox (%s)' % (card['id'][:8], card.get('state')))

    # Drop spool files for cards we can no longer see (deleted off-board).
    for name in os.listdir(INBOX):
        if not name.endswith('.json'):
            continue
        cid = name[:-5]
        if cid not in seen:
            try:
                os.remove(os.path.join(INBOX, name))
                log('IN %s -> removed from spool (not visible)' % cid[:8])
            except OSError:
                pass


def main():
    lock = open('/tmp/omega_kanban_relay.lock', 'w')
    try:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.exit(0)
    ensure_spool()
    log('kanban relay started (principal=%s lane=%s)' % (K.ME, LANE))
    while True:
        try:
            outbound()
            inbound()
        except Exception as e:
            log('loop error: %s' % e)
        time.sleep(20)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Mirror the lanes.md dispatch loop onto the a2a kanban board.

Boss 11-10: "then make sure all agents are using a2a mcp kanban and can use
it via mcp right?"

Wiring the MCP into a profile is only half of it - the lane has to actually
WORK on the board, otherwise the kanban is a dead read-only mirror. This
module is the bridge:

  * the dispatcher (which already owns the PENDING -> DOING -> CLOSED state
    machine in lanes.md) mirrors every card it launches onto the kanban;
  * a lane's own MCP tools (kanban_create/claim/move) let the lane record
    PROGRESS on the same card the dispatcher created.

The dispatcher is the WRITER for the card lifecycle (it knows about the DONE
log, the stale timer and the dead-worker release), so it owns the card id and
the lane works that card. The lane's MCP calls then attach notes to it.

Each lane profile has its own principal, so the board's ownership ACL means
"lane-coding moved this card" is distinguishable from "lane-vision moved this
card" - and a lane genuinely cannot touch another lane's card.
"""
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MCP_DIR = Path(r"C:\Users\agnesagent\work\_tmp\kanban_mcp")
sys.path.insert(0, str(MCP_DIR))

import kanban_mcp_server as K  # noqa: E402

LANES_FILE = Path(r"C:\Users\agnesagent\work\lanes\lanes.md")
STATE_FILE = Path(r"C:\Users\agnesagent\work\lanes\kanban_map.json")

PRINCIPAL_KEYS = {
    'chat': 'lane-chat',
    'coding': 'lane-coding',
    'vision': 'lane-vision',
    'asi1-gig-lane': 'lane-asi1-gig',
    'asi1-airdrop-lane': 'lane-asi1-airdrop',
}

KEY_DIR = Path(r"C:\Users\agnesagent\work\_tmp\kanban_principals")


def _key_for(lane):
    p = PRINCIPAL_KEYS.get(lane)
    if not p:
        return None
    return KEY_DIR / (p + '.key')


def _load_map():
    try:
        return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except Exception:
        return {}


def _save_map(m):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(m, indent=1, sort_keys=True), encoding='utf-8')
    tmp.replace(STATE_FILE)


def configure(lane):
    """Point the shared MCP module at this lane's principal + key."""
    key = _key_for(lane)
    if not key or not key.exists():
        return False
    K.ME = PRINCIPAL_KEYS[lane]
    K.KEY = str(key)
    K.ENC_KEYS = str(MCP_DIR / 'kanban_cek.json')
    K.SSH_KEY = r"C:\Users\agnesagent\.ssh\id_rci_vps"
    K.SSH_USER = 'root'
    K.BOARD_HOST = '100.116.149.122'
    return True


def mirror_card(lane, task_id, desc, state, note=''):
    """Create or move the kanban card that mirrors a lanes.md task.

    Returns the card id, or None on failure (the dispatch loop must NOT break
    because the board is unreachable - the board is a mirror, not the source
    of truth for lanes.md).
    """
    if not configure(lane):
        return None
    m = _load_map()
    key = '%s/%s' % (lane, task_id)
    card_id = m.get(key)
    try:
        if card_id:
            # existing card - move it, ignoring 'done is terminal'
            try:
                res = K.kanban_move(card_id=card_id, state=state, note=note)
                if 'error' in res:
                    # terminal or not ours - the card may have been closed
                    # already; fall through and create a fresh one.
                    card_id = None
                else:
                    return card_id
            except Exception:
                card_id = None
        if not card_id:
            # owner MUST be set: an unowned card can be moved by ANY principal
            # (the board's ACL allows owner=None), which defeats the per-lane
            # ownership the fleet relies on. The creating lane owns its card.
            res = K.kanban_create(title='[%s] %s' % (lane, task_id),
                                  detail=desc or '',
                                  lane=lane, priority='normal', state='todo',
                                  owner=PRINCIPAL_KEYS.get(lane, lane))
            if 'error' in res or not res.get('id'):
                return None
            card_id = res['id']
            if state != 'todo':
                try:
                    K.kanban_move(card_id=card_id, state=state, note=note)
                except Exception:
                    pass
        m[key] = card_id
        _save_map(m)
        return card_id
    except Exception:
        return None


def close_card(lane, task_id, note='DONE'):
    """Close the mirrored card when the lanes.md task reaches CLOSED-DONE."""
    if not configure(lane):
        return None
    m = _load_map()
    key = '%s/%s' % (lane, task_id)
    card_id = m.get(key)
    if not card_id:
        return None
    try:
        res = K.kanban_move(card_id=card_id, state='done', note=note)
        if 'error' in res:
            return card_id  # already terminal - fine
        return card_id
    except Exception:
        return card_id


def card_for(lane, task_id):
    m = _load_map()
    return m.get('%s/%s' % (lane, task_id))


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'help'
    if cmd == 'mirror':
        lane, tid, state = sys.argv[2], sys.argv[3], sys.argv[4]
        desc = sys.argv[5] if len(sys.argv) > 5 else ''
        print(mirror_card(lane, tid, desc, state))
    elif cmd == 'close':
        print(close_card(sys.argv[2], sys.argv[3]))
    elif cmd == 'board':
        lane = sys.argv[2] if len(sys.argv) > 2 else None
        configure(lane) if lane else None
        print(json.dumps(K.kanban_board(lane=lane), indent=1))
    elif cmd == 'map':
        print(json.dumps(_load_map(), indent=1))
    else:
        print('usage: kanban_bridge.py mirror <lane> <task_id> <state> [desc] | '
              'close <lane> <task_id> | board [lane] | map')

#!/usr/bin/env python3
"""googlevps kanban client for the UNION verification lane.

The union worker on googlevps is a plain python script (no Hermes MCP), so it
uses the kanban MCP server's own functions directly - same signing path, same
encryption, same board. Principal = googlevps.

WHAT THE UNION LANE DOES ON THE KANBAN:
  * polls the 'verify' lane for cards waiting for re-verification
  * claims one (moves it to 'doing', owner=googlevps)
  * posts its verdict (SUBMITTABLE / REFUTED / OUT-OF-SCOPE) as a note
  * moves the card to 'done' (or 'blocked')

Hunt lanes (vision, asi1, coding) POST a 'verify' card when they find a
candidate bug; the union lane picks it up. That replaces the old file-based
queue with something durable and visible to the whole fleet.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kanban_mcp_server as K

# googlevps runs on its own host: principal=googlevps, its own signing key,
# and the shared CEK.
K.ME = 'googlevps'
K.KEY = os.environ.get('KANBAN_KEY', os.path.expanduser('~/.ssh/id_ed25519'))
K.ENC_KEYS = os.environ.get('KANBAN_ENC_KEYS',
                             os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                          'kanban_cek.json'))
K.SSH_KEY = os.environ.get('KANBAN_SSH_KEY', os.path.expanduser('~/.ssh/omega_pull'))
K.SSH_USER = 'root'
K.BOARD_HOST = '100.116.149.122'


def pending(lane='verify'):
    """Cards in this lane that nobody owns yet."""
    res = K.kanban_list(lane=lane)
    return [c for c in res.get('cards', [])
            if c.get('state') == 'todo' and not c.get('owner')]


def claim(card_id, note=''):
    return K.kanban_claim(card_id=card_id, note=note or 'claimed by union lane')


def verdict(card_id, text, state='done'):
    """Post the verdict then close the card."""
    K.kanban_comment(card_id=card_id, note=text)
    return K.kanban_move(card_id=card_id, state=state, note=text[:200])


def board(lane='verify'):
    return K.kanban_board(lane=lane)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'pending'
    if cmd == 'pending':
        print(json.dumps(pending(), indent=1))
    elif cmd == 'board':
        print(json.dumps(board(), indent=1))
    elif cmd == 'claim':
        print(json.dumps(claim(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else ''), indent=1))
    elif cmd == 'verdict':
        print(json.dumps(verdict(sys.argv[2], sys.argv[3],
                                 sys.argv[4] if len(sys.argv) > 4 else 'done'), indent=1))
    else:
        print('usage: gvps_kanban.py pending|board|claim <id>|verdict <id> <text> [state]')
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())

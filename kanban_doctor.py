#!/usr/bin/env python3
"""kanban_doctor.py - preflight for the a2a kanban MCP client.

Run this BEFORE you wire a profile, and again whenever a lane "cannot see the
board". It checks every moving part that has actually broken in practice, in
the order it breaks:

  1. python / AES-GCM backend     - no backend => every create/read fails closed
  2. ssh-keygen on PATH           - signing is done by ssh-keygen -Y sign
  3. signing key present + 0600   - the lane's ed25519 identity
  4. shared CEK present + 0600    - shared card key (server never holds it)
  5. signing key matches roster   - a key that is not in roster.json is an
                                    unknown principal; the board rejects it
  6. ssh to the board host        - BatchMode, no password prompt allowed
  7. live board round-trip        - kanban_list against the real board
  8. decrypt a card body          - proves the CEK is the RIGHT CEK

Usage:
  set KANBAN_PRINCIPAL / KANBAN_KEY / KANBAN_ENC_KEYS / KANBAN_BOARD_HOST /
      KANBAN_SSH_KEY  (same env the MCP server gets)
  python kanban_doctor.py            # checks 1-7 (no writes)
  python kanban_doctor.py --live     # also do the round-trip (7) and decrypt (8)

Exit code 0 = all green, 1 = at least one FAIL.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

OK, FAIL, WARN = 'OK  ', 'FAIL', 'WARN'
results = []


def rec(status, name, detail=''):
    results.append((status, name, detail))
    print('%s %-34s %s' % (status, name, detail))


def check_backend():
    try:
        import kanban_enc  # noqa: F401
        rec(OK, 'aes-256-gcm backend', getattr(kanban_enc, 'BACKEND', 'available'))
        return True
    except Exception as e:
        rec(FAIL, 'aes-256-gcm backend', '%s (pip install pycryptodome)' % e)
        return False


def check_ssh_keygen():
    try:
        out = subprocess.run(['ssh-keygen', '-?'], capture_output=True, text=True)
        banner = (out.stdout or out.stderr).splitlines()[0] if (out.stdout or out.stderr) else 'present'
        rec(OK, 'ssh-keygen', banner.strip()[:60])
        return True
    except Exception as e:
        rec(FAIL, 'ssh-keygen', 'not on PATH (%s)' % e)
        return False


def check_secret_file(name, path):
    if not path:
        rec(FAIL, name, 'path not set')
        return False
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        rec(FAIL, name, 'missing: %s' % path)
        return False
    st = os.stat(path)
    mode = oct(st.st_mode & 0o777)
    if st.st_mode & 0o077:
        rec(WARN, name, '%s mode %s - tighten with chmod 600' % (path, mode))
    else:
        rec(OK, name, '%s %s' % (path, mode))
    return True


def roster_key_for(principal, ssh_key):
    """Read the principal's authorized key from a LOCAL copy of roster.json.

    NOTE: KANBAN_ROSTER is the path of roster.json ON THE BOARD HOST (it is
    passed to the remote board script). The local copy is KANBAN_ROSTER_LOCAL,
    default ./roster.json next to this script - pointing the board at a local
    Windows path is what makes the board die with FileNotFoundError.
    """
    roster_path = os.environ.get('KANBAN_ROSTER_LOCAL', os.path.join(HERE, 'roster.json'))
    try:
        with open(roster_path) as f:
            roster = json.load(f)
    except Exception as e:
        rec(WARN, 'roster.json', 'cannot read %s (%s)' % (roster_path, e))
        return None
    entry = roster.get(principal)
    if not entry:
        rec(FAIL, 'principal in roster', '%r is NOT in roster.json - board will reject it' % principal)
        return None
    rec(OK, 'principal in roster', principal)
    want = ' '.join(entry['key'].split()[:2])
    try:
        pub = subprocess.run(['ssh-keygen', '-y', '-f', ssh_key], capture_output=True, text=True)
        got = ' '.join(pub.stdout.split()[:2])
    except Exception as e:
        rec(WARN, 'signing key in roster', 'cannot derive pub (%s)' % e)
        return want
    if got == want:
        rec(OK, 'signing key in roster', 'matches')
    else:
        rec(FAIL, 'signing key in roster', 'local key != roster key for %s' % principal)
    return want


def check_ssh(host, ssh_key, user='root'):
    cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
           '-o', 'StrictHostKeyChecking=accept-new',
           '-i', os.path.expanduser(ssh_key), '%s@%s' % (user, host), 'echo board-host-ok']
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        rec(FAIL, 'ssh to board host', '%s (%s)' % (host, e))
        return False
    if 'board-host-ok' in r.stdout:
        rec(OK, 'ssh to board host', host)
        return True
    rec(FAIL, 'ssh to board host', (r.stderr or r.stdout).strip()[:110])
    return False


def check_live():
    try:
        import kanban_mcp_server as K
    except Exception as e:
        rec(FAIL, 'import kanban_mcp_server', str(e))
        return False
    try:
        res = K.kanban_list()
    except Exception as e:
        rec(FAIL, 'live board round-trip', str(e)[:110])
        return False
    if isinstance(res, dict) and res.get('error'):
        rec(FAIL, 'live board round-trip', str(res['error'])[:110])
        return False
    items = res.get('cards', []) if isinstance(res, dict) else (res or [])
    rec(OK, 'live board round-trip', '%d card(s) visible' % len(items))
    if not items:
        rec(WARN, 'decrypt card body', 'no cards visible for this principal')
        return True
    # list does NOT return detail (by design) - get does. get() decrypts the
    # body with the CEK, so a readable body proves the CEK is the right one.
    try:
        one = K.kanban_get(items[0]['id'])
    except Exception as e:
        rec(FAIL, 'decrypt card body', str(e)[:110])
        return False
    body = one.get('detail') if isinstance(one, dict) else None
    if isinstance(body, str) and body.startswith('kanban-enc-v1:'):
        rec(FAIL, 'decrypt card body', 'still ciphertext - CEK/kanban_enc mismatch')
        return False
    rec(OK, 'decrypt card body', repr(body or '')[:50])
    return True


def main():
    live = '--live' in sys.argv
    principal = os.environ.get('KANBAN_PRINCIPAL', 'rci-vps')
    key = os.environ.get('KANBAN_KEY', os.path.expanduser('~/.ssh/id_ed25519'))
    cek = os.environ.get('KANBAN_ENC_KEYS', '/opt/kanban-mcp/kanban_cek.json')
    host = os.environ.get('KANBAN_BOARD_HOST', '100.116.149.122')
    ssh_key = os.environ.get('KANBAN_SSH_KEY', os.path.expanduser('~/.ssh/id_rci_vps'))

    print('a2a-kanban doctor  principal=%s  board=%s\n' % (principal, host))
    check_backend()
    check_ssh_keygen()
    check_secret_file('signing key', key)
    check_secret_file('shared CEK', cek)
    roster_key_for(principal, os.path.expanduser(key))
    check_ssh(host, ssh_key, os.environ.get('KANBAN_SSH_USER', 'root'))
    if live:
        check_live()
    else:
        print('     (skipped live round-trip - add --live)')

    fails = [r for r in results if r[0] == FAIL]
    print('\n%d check(s), %d failed' % (len(results), len(fails)))
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())

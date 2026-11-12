"""Card-body encryption for the a2a KANBAN board (AES-256-GCM, shared CEK).

WHY THIS EXISTS (boss 11-10): the kanban board is the durable task store that
replaces the transient bulletin board. Card DETAIL and transition NOTES are the
substantive content an agent wrote, so they must not sit in the SQLite file in
plaintext.

HOW IT DIFFERS FROM mesh_enc.py (the MESSAGE board encryption):
  * mesh_enc.py  -> PER-RECIPIENT key. A message has exactly one recipient, so
                     the board can store ciphertext it cannot read. AAD binds
                     (sender, recipient, msg_id).
  * kanban_enc.py -> ONE SHARED key ("kanban CEK") held by every roster
                     principal. A card is SHARED state: the owner moves it and
                     every other agent must be able to LIST it and read it, so a
                     per-recipient key would make the board unusable. The AAD
                     binds (board, card_id) only - NOT the principal - so any
                     principal holding the shared CEK can decrypt.

CONSEQUENCE: the board process never holds the CEK. It stores and returns
ciphertext; only an MCP client (which holds the CEK) decrypts. Plaintext never
touches the board DB.

Wire format: "kanban-enc-v1:<b64 nonce>:<b64 ciphertext+tag>".

Fails CLOSED: if no AES-256-GCM backend is available, encrypt/decrypt raise and
the MCP client refuses to create or read cards rather than silently sending
plaintext.
"""
import base64
import binascii
import hashlib
import json
import os
import secrets
from pathlib import Path

ENC_PREFIX = 'kanban-enc-v1'
NONCE_LEN = 12
KEY_LEN = 32

_BACKEND = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    _BACKEND = 'cryptography'
except ImportError:
    try:
        from Crypto.Cipher import AES as _PyCryptoAES  # pycryptodome (Termux phones)
        _BACKEND = 'pycryptodome'
    except ImportError:
        _AESGCM = None
        _PyCryptoAES = None


def _backend():
    if _BACKEND is None:
        raise RuntimeError(
            'no AES-256-GCM backend (pip install cryptography or pycryptodome); '
            'refusing to store or read plaintext cards')
    return _BACKEND


def _aead_encrypt(key, nonce, plaintext, aad):
    if _backend() == 'cryptography':
        return _AESGCM(key).encrypt(nonce, plaintext, aad)
    c = _PyCryptoAES.new(key, _PyCryptoAES.MODE_GCM, nonce=nonce, mac_len=16)
    if aad:
        c.update(aad)
    ct, tag = c.encrypt_and_digest(plaintext)
    return ct + tag


def _aead_decrypt(key, nonce, ciphertext_and_tag, aad):
    if _backend() == 'cryptography':
        return _AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)
    ct, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    c = _PyCryptoAES.new(key, _PyCryptoAES.MODE_GCM, nonce=nonce, mac_len=16)
    if aad:
        c.update(aad)
    return c.decrypt_and_verify(ct, tag)


def _aad(board, card_id):
    # Binds the ciphertext to ONE card on ONE board. Not bound to a principal:
    # a card is shared state that every roster principal must be able to read.
    return ('%s|%s|%s' % (ENC_PREFIX, board, card_id)).encode('utf-8')


class KanbanKeyFile:
    """Root-only JSON: {"board": "...", "cek": "<base64 32 bytes>"}."""

    def __init__(self, path):
        self.path = Path(path)
        data = json.loads(self.path.read_bytes())
        if not isinstance(data, dict) or 'cek' not in data:
            raise ValueError('kanban key file schema')
        cek = base64.b64decode(data['cek'], validate=True)
        if len(cek) != KEY_LEN:
            raise ValueError('kanban CEK length')
        self.board = data.get('board', '')
        self.cek = cek
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


def new_cek():
    return secrets.token_bytes(KEY_LEN)


def write_key_file(path, cek, board):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {'board': board, 'cek': base64.b64encode(cek).decode()}
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, sort_keys=True, indent=1))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(p)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def encrypt(cek, board, card_id, plaintext):
    """Encrypt a UTF-8 string for a card. Returns the kanban-enc-v1 wire string."""
    _backend()
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    if not plaintext:
        return ''
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = _aead_encrypt(cek, nonce, plaintext.encode('utf-8'), _aad(board, card_id))
    return '%s:%s:%s' % (ENC_PREFIX,
                         base64.b64encode(nonce).decode(),
                         base64.b64encode(ct).decode())


def decrypt(cek, board, card_id, wire):
    """Decrypt a kanban-enc-v1 wire string. Raises ValueError on any tampering,
    wrong key, or format drift."""
    _backend()
    parts = wire.split(':')
    if len(parts) != 3 or parts[0] != ENC_PREFIX:
        raise ValueError('not a kanban-encrypted field')
    try:
        nonce = base64.b64decode(parts[1], validate=True)
        ct = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('kanban enc encoding')
    if len(nonce) != NONCE_LEN:
        raise ValueError('kanban enc nonce length')
    pt = _aead_decrypt(cek, nonce, ct, _aad(board, card_id))
    return pt.decode('utf-8')


def is_encrypted(value):
    return isinstance(value, str) and value.startswith(ENC_PREFIX + ':')

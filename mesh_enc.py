"""Per-recipient message-body encryption for the mesh board (AES-256-GCM).

Design (boss rule: add per-recipient encryption to the MCP, not just signatures):
- Every roster principal owns a random 32-byte content-encryption key (CEK).
- The SENDER encrypts each message body with the RECIPIENT's CEK:
  AES-256-GCM, fresh 12-byte random nonce per message, AAD = the canonical
  signed envelope fields that identify the message (board + sender + recipient
  + message id), so a ciphertext cannot be transplanted into another envelope.
- Wire format replacing the plaintext body: "enc-v1:<b64 nonce>:<b64 ct>".
  The board stores and relays only this opaque string; it never sees plaintext.
- The RECIPIENT (mesh_mcp_server on read) verifies the sender signature first,
  then decrypts with its own CEK. Plaintext never touches the board DB.
- Key custody: each device holds ONLY its own CEK plus the hub's CEK (it needs
  the hub's to encrypt outbound; spokes talk only to the hub). The hub (rci-vps)
  holds every principal's CEK. Keys live in a root-only JSON file per host and
  are never logged or printed.

Requires the `cryptography` package (AESGCM). A pure-stdlib ChaCha20 fallback
would be weaker; if `cryptography` is missing, encryption tools fail CLOSED
(they refuse to send plaintext bodies).
"""
import base64
import binascii
import hashlib
import json
import os
import secrets
from pathlib import Path

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
        raise RuntimeError('no AES-256-GCM backend (install cryptography or pycryptodome); refusing plaintext send')
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

ENC_PREFIX = 'enc-v1'
NONCE_LEN = 12
KEY_LEN = 32


class EncKeyFile:
    """Root-only JSON map {principal: base64 CEK} on the local host."""

    def __init__(self, path):
        self.path = Path(path)
        raw = self.path.read_bytes()
        data = json.loads(raw)
        if not isinstance(data, dict) or not data:
            raise ValueError('enc key file schema')
        self.keys = {}
        for name, key in data.items():
            if not isinstance(name, str) or not name or not isinstance(key, str):
                raise ValueError('enc key entry')
            k = base64.b64decode(key, validate=True)
            if len(k) != KEY_LEN:
                raise ValueError('enc key length for ' + name)
            self.keys[name] = k
        # Enforce private perms where we can (POSIX); on Windows this is a no-op.
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self, principal):
        k = self.keys.get(principal)
        if k is None:
            raise KeyError('no encryption key for principal ' + principal)
        return k


def new_key():
    return secrets.token_bytes(KEY_LEN)


def _aad(sender, recipient, msg_id):
    # AAD binds the ciphertext to this exact message on this board.
    return ('mesh-enc-v1|%s|%s|%s' % (sender, recipient, msg_id)).encode()


def encrypt(recipient_key, sender, recipient, msg_id, plaintext):
    """Encrypt a UTF-8 body for one recipient. Returns the enc-v1 wire string."""
    _backend()
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if not plaintext:
        raise ValueError('empty body')
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = _aead_encrypt(recipient_key, nonce, plaintext, _aad(sender, recipient, msg_id))
    return '%s:%s:%s' % (ENC_PREFIX,
                         base64.b64encode(nonce).decode(),
                         base64.b64encode(ct).decode())


def decrypt(own_key, sender, recipient, msg_id, wire_body):
    """Decrypt an enc-v1 wire body. Returns bytes. Raises ValueError on any
    tampering/auth failure (GCM tag), wrong recipient key, or format drift."""
    _backend()
    parts = wire_body.split(':')
    if len(parts) != 3 or parts[0] != ENC_PREFIX:
        raise ValueError('not an encrypted body')
    try:
        nonce = base64.b64decode(parts[1], validate=True)
        ct = base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('enc body encoding')
    if len(nonce) != NONCE_LEN:
        raise ValueError('enc nonce length')
    pt = _aead_decrypt(own_key, nonce, ct, _aad(sender, recipient, msg_id))
    return pt


def is_encrypted(body):
    return isinstance(body, str) and body.startswith(ENC_PREFIX + ':')


def write_key_file(path, keys: dict):
    """Atomically write {principal: bytes-CEK} as base64 JSON, mode 0600."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {name: base64.b64encode(k).decode() for name, k in keys.items()}
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, sort_keys=True, indent=1))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(p)
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]

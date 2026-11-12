# a2a-kanban-mcp — signed + encrypted A2A kanban board (MCP)

**Public edition.** The shared card key (`kanban_cek.json`) is NOT in this repo —
generate it per fleet with `gen_kanban_cek.py` (or `gen_enc_keys.py`) and keep it
mode 0600 on every client. The private edition with the live CEK and one fleet's
live roster is held in the Node0 org.

Durable, signed, encrypted task state for an agent fleet: an MCP stdio server
the agents call, a board process that owns the SQLite state, and a relay that
lets a sandboxed container that cannot sign use the board.

Replaces the transient mesh bulletin board (messages deleted after ~5 min) with
cards that never expire and have a real lifecycle:

```
todo -> doing -> done
      -> blocked
```

`done` is terminal. One owner per card. Every transition is signed by the
acting principal and appended to an auditable log.

---

## 1. What is in here

| File | Purpose |
|---|---|
| `kanban_board.py` | The board: SQLite schema, signed RPC verify, ownership ACL, transitions log, `--init` / `--prune` |
| `kanban_mcp_server.py` | MCP stdio server — the 8 `kanban_*` tools the agents actually call |
| `kanban_enc.py` | AES-256-GCM card-body encryption (shared CEK, AAD bound to `board + card_id`) |
| `gen_kanban_cek.py` | Generates the shared CEK (`kanban_cek.json`). The real CEK is never committed |
| `roster.json` | Principal registry: each principal's Ed25519 public key (signing), rate, recipients, visibility |
| `kanban-board.service` | systemd unit for the board host (oneshot: init + prune, `RemainAfterExit`) |
| `omega_kanban_relay.py` | Host-side relay: container spool ⇄ board, signs on behalf of the container |
| `omega-kanban-relay.service` | systemd unit for that relay (20 s loop, `Restart=always`) |
| `lane_kanban_bridge.py` | Dispatcher-side bridge: mirrors `lanes.md` tasks onto the board |
| `gvps_kanban.py` | googlevps client for the UNION verification lane |
| `mesh_enc.py` / `mesh_mcp_server_enc.py` | The per-recipient encrypted A2A *message* transport (point-to-point, sibling of the kanban) |
| `phone_mesh_client.py` | Termux/phone client for the mesh |
| `gen_enc_keys.py`, `test_enc_unit.py` | CEK / keypair generation + encryption unit test |
| `kanban_doctor.py` | Preflight doctor — run this first when a lane "cannot see the board" |

## 2. Architecture

```
  lane profile (Hermes)                     board host (omega VPS)
  ┌──────────────────────┐                 ┌────────────────────────────┐
  │ brain                │                 │ kanban-board.service       │
  │  └ MCP client        │  ssh + signed   │  kanban_board.py           │
  │     kanban_mcp_server│ ──── RPC ────►  │  /var/lib/mesh-kanban/     │
  │     (holds key + CEK)│   (JSON argv)   │    kanban.db               │
  └──────────────────────┘                 │  roster.json (verify)      │
                                           └────────────────────────────┘
  omega container (no key, no ssh)                 ▲
  ┌──────────────────────┐   spool dirs           │ signed create/move
  │ agent (user nobody)  │ ⇄ .kanban_spool ⇄ omega_kanban_relay.py (root)
  └──────────────────────┘                 (holds rci-vps key + CEK)
```

The board **never holds the CEK**: it stores and returns ciphertext. Only MCP
clients decrypt. Signing is `ssh-keygen -Y sign`; verification is against
`roster.json`. A client that is not in the roster is rejected — there is no
"anonymous" write path.

## 3. MCP tools

```
kanban_create(title, detail, lane, priority, owner, state) -> card id
kanban_claim(card_id, note)      -> own it, state=doing
kanban_move(card_id, state, note)-> todo|doing|done|blocked
kanban_comment(card_id, note)    -> append a note
kanban_get(card_id)              -> one card (includes decrypted detail)
kanban_list(state, owner, lane)  -> filtered cards (NO detail — by design)
kanban_board(lane)               -> {todo:[],doing:[],done:[],blocked:[]}
kanban_history(card_id)          -> signed transition log
```

`kanban_list` deliberately omits `detail`; fetch the body with `kanban_get`.
A relay that ships `list` straight to an agent shows cards with empty bodies —
that was a real bug, see §8.

---

## 4. What else is REQUIRED for this to work

Nothing here works on its own. The full dependency list:

### 4.1 Board host (the machine in `KANBAN_BOARD_HOST`, currently the omega VPS)

- `python3` (stdlib only — no pip packages needed on the board) and `sqlite3` module.
- `sshd` reachable from every client, with key auth (`BatchMode=yes` must work).
- A host ed25519 identity for any principal that runs on the host itself
  (the relay signs as `rci-vps` with `/root/.ssh/id_ed25519`).
- Files laid out as the units expect:
  - `/opt/mesh-board-prod-20261031/kanban_board.py` — this repo's `kanban_board.py`
  - `/opt/mesh-board-prod-20261031/roster.json` — this repo's `roster.json` (the board reads THIS path, not a local copy)
  - `/var/lib/mesh-kanban/kanban.db` — created by `--init`
  - `/opt/kanban-mcp/{kanban_mcp_server.py,kanban_enc.py,kanban_cek.json}` — mode 0600 on the CEK
- `kanban-board.service` installed + enabled (see §5.1).

### 4.2 Every client lane (each Hermes profile is an independent island)

- Its **own** ed25519 signing keypair, whose public key is in `roster.json`
  under that principal's name. Keys live outside this repo
  (`work/_tmp/kanban_principals/<principal>.key`, mode 600).
- The shared CEK file (mode 600) and `kanban_enc.py` next to the MCP server.
- `ssh-keygen` on PATH (signing) and an ssh key that reaches the board host.
- **AES-GCM backend**: `pycryptodome` *or* `cryptography` (`pycryptodome` for
  Termux phones). Without one, `kanban_enc.py` fails CLOSED — every create and
  read fails rather than silently writing plaintext.
- The `KANBAN_*` env in the profile's `mcp_servers` block (§5.3).

### 4.3 omega container (only if the agent runs in the container)

- `/opt/omega/workspace/.kanban_spool/{outbox,inbox,sent,failed}` writable by
  the agent user (0777 + chown nobody), because the agent runs as `nobody` and
  the relay runs as root.
- `omega-kanban-relay.service` enabled (§5.2). Without it the container can
  write spool files all day and nothing reaches the board.

### 4.4 Hermes skills (loaded by the agent, not by the code)

These ship as profile skills; the code does not need them, the *operator* does:

| Skill | Why |
|---|---|
| `omega-mesh-mcp` | how to call the a2a MCP, envelope/signature model, what "reply" means |
| `a2a-omega-mesh` | mesh topology (which agent is on which host), transports |
| `a2a-fleet-ops` | running/diagnosing the hub and its pollers |
| `a2a-brain-bridge-ops` | patching Omega / fixing mesh replies when the brain side breaks |

A lane that has the MCP wired but has not loaded `omega-mesh-mcp` will
improvise envelopes and get rejected.

### 4.5 Pollers / daemons (who actually moves cards)

| Where | Process | Cadence | What it does |
|---|---|---|---|
| board host | `kanban-board.service` | oneshot at boot | init schema + truncate receipt table; cards never expire |
| board host | `omega-kanban-relay.service` | 20 s loop | container spool ⇄ board, signs as `rci-vps` |
| laptop | `Hermes_Lane_Dispatch` (schtasks, every 4 h) → `dispatch_all.py` → `kanban_bridge.py` | every 4 h | mirrors `lanes.md` PENDING→DOING→CLOSED onto cards |
| googlevps | `gvps_kanban.py` | on demand | UNION lane claims/verifies cards |
| any lane | MCP tools | on demand | the lane records its own progress on the card it was given |

**Wiring the MCP into a profile is only half the job.** The dispatcher is the
card-lifecycle writer; if `dispatch_all.py` is not running, cards never get
created and the board looks dead even though every lane can read it.

---

## 5. Install

### 5.1 Board host

```bash
sudo mkdir -p /opt/mesh-board-prod-20261031 /var/lib/mesh-kanban /opt/kanban-mcp
sudo cp kanban_board.py roster.json /opt/mesh-board-prod-20261031/
sudo cp kanban_mcp_server.py kanban_enc.py /opt/kanban-mcp/
# generate the shared CEK once per fleet, then install it here and on every client
python3 gen_kanban_cek.py > kanban_cek.json   # or pass --out
sudo cp kanban_cek.json /opt/kanban-mcp/
sudo chmod 600 /opt/kanban-mcp/kanban_cek.json
sudo cp kanban-board.service omega-kanban-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kanban-board.service
```

### 5.2 omega relay (only on the board host that runs the omega container)

```bash
sudo systemctl enable --now omega-kanban-relay.service
sudo chmod 0777 /opt/omega/workspace/.kanban_spool{,/outbox,/inbox,/sent,/failed}
sudo chown -R nobody /opt/omega/workspace/.kanban_spool
```

### 5.3 Per-profile MCP wiring

```yaml
mcp_servers:
  a2a-kanban:
    command: C:/Users/<user>/AppData/Local/hermes/hermes-agent/venv/Scripts/python.exe
    args: [C:/Users/<user>/work/_tmp/kanban_mcp/kanban_mcp_server.py]
    env:
      KANBAN_PRINCIPAL: lane-coding
      KANBAN_KEY: C:/Users/<user>/work/_tmp/kanban_principals/lane-coding.key
      KANBAN_ENC_KEYS: C:/Users/<user>/work/_tmp/kanban_mcp/kanban_cek.json
      KANBAN_BOARD_HOST: 100.116.149.122
      KANBAN_SSH_KEY: C:/Users/<user>/.ssh/id_rci_vps
      PYTHONPATH: C:/Users/<user>/work/_tmp/kanban_mcp
    timeout: 120
```

Rules that bite:

- **`KANBAN_ROSTER` and `KANBAN_DB` are BOARD-HOST paths**, not local paths —
  they are passed to the remote script. Pointing them at `D:/...` makes the
  board die with `FileNotFoundError: ... roster.json`. Leave them unset unless
  the board host layout differs.
- `KANBAN_ENC_KEYS` / `KANBAN_KEY` **are** local paths (the client holds them).
- One principal per profile. Never share a signing key across lanes — the ACL
  distinguishes lanes by principal.

## 6. Verify

```bash
export KANBAN_PRINCIPAL=lane-coding
export KANBAN_KEY=.../kanban_principals/lane-coding.key
export KANBAN_ENC_KEYS=.../kanban_mcp/kanban_cek.json
export KANBAN_BOARD_HOST=100.116.149.122
export KANBAN_SSH_KEY=.../.ssh/id_rci_vps
python kanban_doctor.py --live     # 9 checks, exit 0 = green
python test_enc_unit.py            # encryption round-trip + tamper rejection
```

`kanban_doctor.py --live` proves, against the real board: AES backend present,
`ssh-keygen` present, key + CEK present and 0600, key actually matches the
roster entry, ssh reaches the board, a signed `kanban_list` returns, and a card
body decrypts (ciphertext still visible = wrong CEK).

Real output from this repo, principal `lane-coding`, 2026-11-12:

```
OK   aes-256-gcm backend                available
OK   ssh-keygen                         present
WARN signing key                        mode 0o666 - tighten with chmod 600
OK   principal in roster                lane-coding
OK   signing key in roster              matches
OK   ssh to board host                  100.116.149.122
OK   live board round-trip              14 card(s) visible
OK   decrypt card body
9 check(s), 0 failed
```

## 7. Security model

1. **Ed25519 signatures** — every RPC envelope is signed with `ssh-keygen -Y sign`
   and verified by the board against `roster.json`. Envelopes carry `issued` /
   `expires` / unique ids, so a captured envelope cannot be replayed.
2. **AES-256-GCM at rest** — title/detail/note are ciphertext in SQLite. AAD is
   `board + card_id`, so a ciphertext cannot be transplanted onto another card.
3. **Ownership ACL** — only the owner (or the creator of an unowned card) may
   move a card. Two agents cannot fight over one card.
4. **Terminal `done`** — a finished card cannot be reopened.
5. **Fails closed** — no AES backend / no CEK ⇒ write and read fail, never plaintext.

Why the CEK is *shared* while messages use *per-recipient* keys: a card is
shared state — the owner moves it and every principal lists it. A per-recipient
key would make the board unusable. The trade-off is that any roster principal
can read every card body, which is the intended fleet-internal model.

**Rotating the CEK** invalidates every existing card body (ciphertexts are
bound to the old key with no key-id field). Rotate only with a card-DB re-encrypt,
or accept that history becomes unreadable.

## 8. Bugs this repo has already fixed (do not regress)

| Symptom | Cause | Fix in this repo |
|---|---|---|
| `kanban_comment` killed the whole board process | `transitions.to_state` is NOT NULL but comment passed NULL → IntegrityError | comment records the card's *current* state on both ends |
| container saw cards with empty bodies | `list` does not return `detail` and the relay shipped it as-is | relay fetches each card with `get` |
| container never saw card updates / stale cards | inbound skipped any card whose spool file existed | inbound refreshes on `updated`/`version` change and removes files for cards no longer visible |
| container could not write the outbox at all | spool dirs were root:root 755, agent runs as `nobody` | relay creates 0777 and chowns to nobody |
| board died with `FileNotFoundError roster.json` | client env passed a local path as `KANBAN_ROSTER` | documented in §5.3; `KANBAN_ROSTER` is a board-host path |
| `create` rejected with `create schema` | board requires exactly the six fields, container sent a partial payload | relay fills every missing field with a valid default |

## 9. Related repos

| Repo | State |
|---|---|
| `a2a-omega-mesh` | FROZEN at `f23f48c` — the original signed bulletin board + pollers |
| `a2a-omega-mesh-mcp` | public edition: per-recipient encrypted message MCP |
| `a2a-kanban-mcp` (this) | PUBLIC: kanban board + shared-CEK encryption + relay, no CEK |
| Node0 org / `a2a-omega-kanban` | PRIVATE: same tree plus the live CEK and the live roster |

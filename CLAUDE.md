# CLAUDE.md — Project Context for Claude Code

## What This Project Is

NYU CS6903/4783 Applied Cryptography, Spring 2026 — Project 2.2.

A Python command-line tool that provides **end-to-end encrypted group messaging over Slack**. Slack is treated as an untrusted transport relay. All cryptographic operations happen locally on sender/recipient machines. Slack never sees plaintext.

## Project Structure

```
crypto.py          # All crypto ops — no Slack calls, no file I/O beyond key loading
state.py           # Replay prevention (sequence counters) + group key state
slack_interface.py # Slack API only — post_message, fetch_messages
padding.py         # Optional fixed-size padding for traffic analysis mitigation
client.py          # CLI entry point — argparse wiring all modules
keys/              # Generated keypairs (PEM) — gitignored
state/             # Runtime JSON state — gitignored
demo/              # Shell scripts for 6 demo scenarios
tests/             # Unit + integration tests
docs/              # Planning docs, PDFs, implementation plan
```

## Cryptographic Design

| Primitive | Algorithm | Reason |
|-----------|-----------|--------|
| Symmetric encryption | AES-256-GCM | Authenticated encryption in one primitive |
| Key agreement | X25519 ECDH + HKDF-SHA256 | 32-byte keys at 128-bit security; HKDF for uniform output |
| Signing | Ed25519 | Deterministic — no per-signature nonce (unlike ECDSA) |
| Group key distribution | Per-member ECDH wrap | Each member gets group key encrypted to their X25519 pubkey |
| Replay prevention | Monotonic sequence counter | Per-sender, persisted in state/sequence_state.json |

**Key rules — never deviate:**
- IV is always `os.urandom(12)` — fresh per message. Reuse = catastrophic.
- Sign the **ciphertext**, not the plaintext.
- Update sequence state **only after** full verification (sig + GCM both pass).
- Sort fetched messages by sequence number **ascending** before processing.
- `crypto.py` has zero side effects — no prints, no file writes except explicit save functions.

## Build Plan (8 Phases)

| Phase | File(s) | Status |
|-------|---------|--------|
| 1 | crypto.py | stub |
| 2 | state.py | stub |
| 3 | slack_interface.py | stub |
| 4 | padding.py | stub |
| 5 | client.py | stub |
| 6 | demo/*.sh | stub |
| 7 | README.md | stub |
| 8 | tests/ | stub |

**Session strategy:** Build Phases 1–4 together (all independent), then Phase 5, then Phases 6–8.

## Attacks Defended Against

1. **Eavesdropping** — AES-256-GCM encryption
2. **Modification** — GCM authentication tag + AAD
3. **Spoofing** — Ed25519 signature over ciphertext
4. **Replay** — monotonic sequence counter per sender

Plus extended analysis: service provider attacks, compromised members, combined attacks, key distribution MITM.

## Message Package Format (what Slack stores)

```json
{
  "version": 1,
  "channel_id": "incident-2026",
  "sender_id": "alice",
  "sequence": 42,
  "timestamp": "2026-03-27T14:00:00Z",
  "iv": "<base64 96-bit nonce>",
  "ciphertext": "<base64 AES-256-GCM ciphertext + 16-byte GCM tag>",
  "signature": "<base64 Ed25519 64-byte signature>"
}
```

## Libraries

- `cryptography` (PyCA / OpenSSL) — all crypto primitives
- `slack_sdk` — Slack API
- `python-dotenv` — `.env` loading for `SLACK_BOT_TOKEN`

## Known Limitations (document these, don't fix them)

- No per-message forward secrecy (would require Double Ratchet)
- Metadata not hidden (sender timing, message sizes visible to Slack)
- No key transparency (fingerprint verification is manual)
- Single admin trust (admin generates and distributes group key)

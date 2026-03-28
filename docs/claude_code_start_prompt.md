# CLAUDE CODE START PROMPT
# NYU CS6903/4783 Project 2.2 — Encrypted Slack Channel for Security Incident Response
# Copy this entire file as your initial prompt to Claude Code

---

## CONTEXT

I am building a Python command-line tool for my NYU Applied Cryptography class (CS6903/4783, Spring 2026). The project is "Project 2.2: Designing an end-to-end cryptography solution to protect your data application from attacks."

The application is an end-to-end encrypted group messaging system that uses Slack as an untrusted transport relay. Slack (including its admins) should never see plaintext. All encryption, signing, and verification happen locally on sender/recipient machines. TLS is explicitly NOT treated as a security mechanism — our crypto layer is the only protection.

The project must defend against four mandatory attacks: data eavesdropping, data modification, data originator spoofing, and data replay. It must also include an expanded security analysis covering combined attacks, service provider attacks, compromised members, and key distribution attacks.

I want you to help me build this project incrementally. I will tell you which phase to work on. Do not build everything at once. Wait for my instructions on which phase to start.

---

## PROJECT STRUCTURE

Create the following directory structure under a folder called `project-2.2/`:

```
project-2.2/
├── client.py              # CLI entry point — argparse, wires all modules
├── crypto.py              # ALL cryptographic operations — no Slack calls, no file I/O beyond key loading
├── slack_interface.py     # Slack API calls only — post_message, fetch_messages
├── state.py               # Replay prevention (sequence counters) + group key state management
├── padding.py             # Optional message padding for traffic analysis mitigation
├── requirements.txt       # cryptography>=41.0.0, slack_sdk>=3.21.0, python-dotenv>=1.0.0
├── README.md              # Setup, usage, security properties, known limitations
├── .env.example           # Template: SLACK_BOT_TOKEN=xoxb-your-token-here
│
├── keys/                  # Generated keypairs (PEM format)
│   └── revoked/           # Revoked member keys moved here on revocation
│
├── state/                 # Runtime state files
│   ├── sequence_state.json
│   └── group_keys.json
│
└── demo/                  # Shell scripts for video demo
    ├── demo_normal.sh
    ├── demo_tamper.sh
    ├── demo_spoof.sh
    ├── demo_replay.sh
    ├── demo_key_rotation.sh
    └── demo_fingerprint.sh
```

---

## PHASE 1: crypto.py — The Cryptographic Engine

This is the most important module. It contains ALL cryptographic operations. It has ZERO Slack API calls and ZERO file I/O (except key loading from PEM files). Every function should raise explicit exceptions on failure.

### Functions to implement:

**Key Generation:**
- `generate_x25519_keypair()` — returns (private_key, public_key) using `X25519PrivateKey.generate()`
- `generate_ed25519_keypair()` — returns (private_key, public_key) using `Ed25519PrivateKey.generate()`
- Two separate keypairs per user: X25519 for key agreement, Ed25519 for signing. NEVER reuse a key across both operations.

**Key Serialization:**
- `save_private_key(key, path)` — PEM, PKCS8, no encryption
- `save_public_key(key, path)` — PEM, SubjectPublicKeyInfo
- `load_x25519_private(path)`, `load_x25519_public(path)` — load from PEM
- `load_ed25519_private(path)`, `load_ed25519_public(path)` — load from PEM

**Key Fingerprinting:**
- `fingerprint(public_key_path: str) -> str` — returns SHA-256 hash of the PEM file contents, formatted as colon-separated hex pairs (e.g., `4a:bf:c3:d9:12:...`)

**Group Key Derivation (ECDH + HKDF):**
- `derive_group_key(my_private_x25519, peer_public_x25519, channel_id: str) -> bytes`
- Perform X25519 DH exchange, then HKDF-SHA256 with length=32, salt=None, info=channel_id.encode('utf-8')
- The raw X25519 output is NOT uniformly distributed — HKDF is mandatory. The channel_id as info ensures keys are domain-separated per channel.

**AES-256-GCM Encryption:**
- `encrypt_message(plaintext: bytes, aes_key: bytes, aad: bytes) -> tuple[bytes, bytes]`
- Returns (ciphertext_with_tag, iv). The Python cryptography library's AESGCM.encrypt() appends the 16-byte GCM tag to the ciphertext automatically.
- iv = os.urandom(12) — 96-bit random nonce, MUST be generated fresh for EVERY message. If the same IV is reused with the same key, GCM security collapses entirely (attacker recovers keystream via XOR of two ciphertexts).
- `decrypt_message(ciphertext_with_tag: bytes, iv: bytes, aes_key: bytes, aad: bytes) -> bytes`
- Raises `cryptography.exceptions.InvalidTag` if ciphertext or AAD has been tampered with. Caller MUST handle this.

**Ed25519 Signing:**
- `build_signed_blob(ciphertext_with_tag, iv, sender_id, sequence, timestamp, channel_id) -> bytes`
- Concatenate all fields with 0x00 separator to prevent field confusion attacks. Hash the result with SHA-256. Return the 32-byte digest. Every field that an attacker could swap or modify MUST be included.
- `sign_message(private_key, signed_blob) -> bytes` — Ed25519 sign
- `verify_signature(public_key, signed_blob, signature) -> None` — raises InvalidSignature on failure

**Why sign ciphertext, not plaintext:** Signing plaintext allows an attacker to strip the signature, re-encrypt under a different key, and attach the original valid signature. Signing the ciphertext binds the signature to the specific encrypted object.

**Group Key Wrapping:**
- `wrap_group_key(group_aes_key, recipient_x25519_public, my_x25519_private, channel_id) -> dict`
- Uses ECDH + HKDF with info = channel_id + ':wrap' to derive a wrapping key, then AES-256-GCM to encrypt the group key. Returns {'ciphertext': base64, 'iv': base64}.
- `unwrap_group_key(wrapped, sender_x25519_public, my_x25519_private, channel_id) -> bytes`

### Cryptographic Library:
- Use `cryptography` (PyCA) which wraps OpenSSL
- Imports: `cryptography.hazmat.primitives.asymmetric.x25519`, `cryptography.hazmat.primitives.asymmetric.ed25519`, `cryptography.hazmat.primitives.ciphers.aead.AESGCM`, `cryptography.hazmat.primitives.kdf.hkdf.HKDF`, `cryptography.hazmat.primitives.hashes.SHA256`

### Design Decisions (implement these, do not deviate):
- AES-256-GCM over AES-CBC: GCM provides authenticated encryption in one primitive. CBC requires a separate HMAC.
- Ed25519 over ECDSA: Ed25519 is deterministic (no per-signature random nonce). ECDSA nonce reuse leaks the private key.
- X25519 over RSA: At 128-bit security, X25519 uses 32-byte keys. RSA equivalent needs 3072 bits.
- HKDF over raw DH output: Raw X25519 output is not uniformly distributed.

---

## PHASE 2: state.py — Replay Prevention and Key State

**Sequence State (replay prevention):**
- `get_last_seq(sender_id: str) -> int` — returns 0 if sender never seen
- `update_seq(sender_id: str, seq: int)` — ONLY call after FULL verification (signature + GCM tag both pass). Never update state on a failed message.
- `is_replay(sender_id: str, seq: int) -> bool` — returns True if seq <= last seen value
- State file: `state/sequence_state.json`

**Group Key State:**
- `init_channel(channel_id, admin_id, key_id, wrapped_keys: dict)` — create channel entry in group_keys.json
- `get_group_key(channel_id, member_id) -> dict` — returns the wrapped key blob for a member
- `add_member_key(channel_id, member_id, wrapped_key: dict)` — add a new member's wrapped key
- `rotate_key(channel_id, new_key_id, new_wrapped_keys: dict)` — replace all wrapped keys with new ones
- `revoke_member(channel_id, member_id)` — remove member from current key, trigger rotation
- State file: `state/group_keys.json`

**group_keys.json schema:**
```json
{
  "incident-2026": {
    "current_key_id": "key-20260327-001",
    "keys": {
      "key-20260327-001": {
        "created_at": "2026-03-27T14:00:00Z",
        "created_by": "alice",
        "members": {
          "alice": {"ciphertext": "...", "iv": "...", "plaintext_hex": "..."},
          "bob": {"ciphertext": "...", "iv": "...", "plaintext_hex": "..."}
        }
      }
    }
  }
}
```

Note: `plaintext_hex` is stored locally for convenience during development/demo. In production this would be derived on each use via unwrapping. For the class demo, storing it locally is acceptable.

---

## PHASE 3: slack_interface.py — Transport Layer

This module handles ONLY Slack API calls. No cryptography here.

- `post_message(channel: str, payload: dict) -> None` — JSON-serialize the payload and post to Slack
- `fetch_messages(channel: str, limit: int = 20) -> list[dict]` — fetch recent messages, parse JSON, skip non-JSON system messages silently
- Uses `slack_sdk.WebClient` with token from environment variable `SLACK_BOT_TOKEN`
- Load token using `python-dotenv`: `from dotenv import load_dotenv; load_dotenv()`

**Slack Bot Setup Requirements (document in README):**
1. Create app at api.slack.com/apps
2. Bot Token Scopes needed: channels:history, channels:read, chat:write
3. Install app to workspace, copy Bot User OAuth Token
4. Store in .env file

---

## PHASE 4: padding.py — Traffic Analysis Mitigation

Optional module. Activated with `--pad` flag on the post command.

- `pad_message(plaintext: bytes, block_size: int = 512) -> bytes`
- Pads plaintext to the next multiple of block_size using PKCS7-style padding (last byte indicates padding length).
- `unpad_message(padded: bytes) -> bytes`
- Reads the last byte to determine padding length, strips padding, validates.

This addresses the expanded security analysis requirement about metadata leakage and traffic analysis.

---

## PHASE 5: client.py — CLI Entry Point

Use `argparse` with subcommands. This module wires together crypto.py, slack_interface.py, state.py, and padding.py.

**Subcommands:**

1. `keygen --name <name>` — Generate X25519 and Ed25519 keypairs, save to keys/ directory
2. `fingerprint --name <name>` — Print SHA-256 fingerprints of both public keys
3. `init-channel --channel <C> --admin <name> --members <name1,name2,...>` — Generate group AES key, wrap for each member, store in group_keys.json
4. `post --channel <C> --sender <name> --message <text> [--pad]` — Full send pipeline:
   - Load sender keys
   - Load group AES key from state
   - Optionally pad the message
   - Build AAD dict: {version, channel_id, sender_id, sequence, timestamp}
   - Encrypt with AES-256-GCM using AAD
   - Build signed blob (includes ciphertext, iv, sender_id, sequence, timestamp, channel_id)
   - Sign with Ed25519
   - Package as JSON and post to Slack
   - Update local sequence counter
5. `fetch --channel <C> --receiver <name> --limit <N> [--check-gaps]` — Full receive pipeline:
   - Fetch messages from Slack
   - Sort by sequence number ascending (critical: prevents the offline-recipient bug where newest-first processing rejects older messages as replays)
   - For each message:
     a. Replay check (is_replay) — reject if seq <= last seen
     b. Load sender's Ed25519 public key, reconstruct signed blob, verify signature — reject if InvalidSignature
     c. Decrypt with AES-256-GCM using reconstructed AAD — reject if InvalidTag
     d. Optionally unpad
     e. Accept: update sequence counter, print plaintext
   - If --check-gaps: after processing, compare expected vs received sequence numbers, warn about gaps
6. `addmember --channel <C> --admin <name> --member <name>` — Wrap group key for new member
7. `revoke --channel <C> --admin <name> --member <name>` — Rotate key excluding revoked member, move their keys to revoked/
8. `rotate --channel <C> --admin <name>` — Generate new group key, re-wrap for all current members
9. `verify --channel <C> --receiver <name>` — Fetch and verify signatures only, no decryption

**Message Package Format (what Slack sees):**
```json
{
  "version": 1,
  "channel_id": "incident-2026-03-27",
  "sender_id": "alice",
  "sequence": 42,
  "timestamp": "2026-03-27T14:00:00Z",
  "iv": "<base64 96-bit nonce>",
  "ciphertext": "<base64 AES-256-GCM ciphertext + 16-byte tag>",
  "signature": "<base64 Ed25519 64-byte signature>"
}
```

There is no separate tag field. AESGCM.encrypt() appends the 16-byte GCM tag to the ciphertext. AESGCM.decrypt() expects and strips it automatically.

---

## PHASE 6: Demo Scripts

Create shell scripts in demo/ for each scenario. These will be run during the video presentation.

**demo_normal.sh:**
```bash
#!/bin/bash
set -e
echo "=== Scenario 1: Normal Flow ==="
python client.py keygen --name alice
python client.py keygen --name bob
python client.py fingerprint --name alice
python client.py fingerprint --name bob
python client.py init-channel --channel incident-2026 --admin alice --members bob
python client.py post --channel incident-2026 --sender alice --message 'Isolate host 10.0.0.5 immediately'
echo "--- Check Slack channel for ciphertext blob ---"
sleep 2
python client.py fetch --channel incident-2026 --receiver bob
```

**demo_tamper.sh:**
```bash
#!/bin/bash
echo "=== Scenario 2: Modification Detected ==="
echo "Manually edit one character in the ciphertext field of the most recent Slack message"
echo "Then run:"
echo "  python client.py fetch --channel incident-2026 --receiver bob"
echo "Expected output: [TAMPER] Decryption failed — message modified"
```

**demo_spoof.sh:**
```bash
#!/bin/bash
echo "=== Scenario 3: Spoofing Rejected ==="
python client.py keygen --name mallory
# Post with mallory's key but claim to be alice
python client.py post --channel incident-2026 --sender mallory --spoof-sender-id alice --message 'Shut down the firewall'
python client.py fetch --channel incident-2026 --receiver bob
# Expected: [SPOOF] Signature invalid for message from alice
```

**demo_replay.sh:**
```bash
#!/bin/bash
echo "=== Scenario 4: Replay Rejected ==="
# Re-post an old message with seq=1 after newer messages exist
python client.py replay --channel incident-2026 --seq 1
python client.py fetch --channel incident-2026 --receiver bob
# Expected: [REPLAY] Rejected message from alice seq=1
```

**demo_key_rotation.sh:**
```bash
#!/bin/bash
echo "=== Scenario 5: Key Lifecycle ==="
python client.py keygen --name carol
python client.py addmember --channel incident-2026 --admin alice --member carol
python client.py post --channel incident-2026 --sender alice --message 'Carol can now read this'
python client.py fetch --channel incident-2026 --receiver carol
# Revoke carol
python client.py revoke --channel incident-2026 --admin alice --member carol
python client.py post --channel incident-2026 --sender alice --message 'Carol cannot read this'
python client.py fetch --channel incident-2026 --receiver carol
# Expected: carol fails to decrypt
```

**demo_fingerprint.sh:**
```bash
#!/bin/bash
echo "=== Scenario 6: Fingerprint Verification ==="
python client.py fingerprint --name alice
python client.py fingerprint --name bob
echo "Compare fingerprints over a trusted channel (in-person, phone call)"
```

---

## PHASE 7: README.md

Write a comprehensive README covering:

1. **Overview** — one paragraph explaining the project
2. **Threat Model** — Slack as untrusted relay, attacker has workspace admin access, TLS is insufficient (explain why: it is encryption in transit, not end-to-end; Slack decrypts TLS at its load balancer)
3. **Setup** — pip install, Slack bot setup, keygen, fingerprint verification protocol
4. **Quick Start** — init-channel, post, fetch
5. **Security Properties** — table of property/mechanism/attack-covered
6. **Extended Threat Analysis** — service provider attacks, compromised members, combined attacks, key distribution attacks, traffic analysis
7. **Design Decisions** — table of decision/justification (AES-GCM over CBC, Ed25519 over ECDSA, sign ciphertext not plaintext, sequence counter over timestamp, X25519 over RSA, HKDF over raw DH, AAD for headers)
8. **Key Trust Model** — fingerprint verification, what happens without it
9. **Known Limitations** — no per-message forward secrecy, metadata visible, no key transparency, single admin trust, no ordering guarantee
10. **CLI Reference** — full command table
11. **Libraries** — cryptography (PyCA) wrapping OpenSSL, slack_sdk

---

## PHASE 8: Testing

After building all modules, run these tests:

1. **Unit tests for crypto.py:**
   - Generate keypair, save, reload, verify they match
   - Encrypt then decrypt — verify plaintext roundtrips
   - Encrypt then tamper with ciphertext — verify InvalidTag
   - Encrypt then tamper with AAD — verify InvalidTag
   - Sign then verify — verify success
   - Sign then tamper with blob — verify InvalidSignature
   - Wrap then unwrap group key — verify roundtrip
   - Fingerprint — verify deterministic output

2. **Unit tests for state.py:**
   - is_replay returns False for new seq, True for old seq
   - update_seq persists across calls
   - init_channel creates correct JSON structure
   - rotate_key replaces all member entries

3. **Integration tests:**
   - Full send/receive cycle without Slack (mock slack_interface)
   - Tampered ciphertext rejection
   - Spoofed sender rejection
   - Replay rejection
   - Key rotation — old member cannot decrypt new messages
   - Gap detection with missing sequence numbers
   - Padding roundtrip

---

## CODING STANDARDS

- Python 3.10+
- Type hints on all function signatures
- Docstrings on all public functions explaining purpose, parameters, return values, and exceptions raised
- No global state except through state.py's file-backed storage
- crypto.py has ZERO side effects (no prints, no file writes except through explicit save functions)
- All exceptions from cryptographic operations must be caught and translated into user-friendly CLI output (e.g., "[TAMPER]", "[SPOOF]", "[REPLAY]")
- Use `python-dotenv` for .env loading
- Use `argparse` for CLI, not click or typer

---

## IMPORTANT NOTES

- Do NOT use TLS as a security mechanism. The project explicitly requires end-to-end encryption independent of transport security.
- Do NOT implement your own cryptographic primitives. Use the `cryptography` library (PyCA/OpenSSL) for all crypto operations.
- The `cryptography` library's AESGCM.encrypt() appends the GCM tag to the ciphertext automatically. Do NOT create a separate tag field.
- IV (nonce) MUST be os.urandom(12) for EVERY message. IV reuse with the same key is a catastrophic security failure.
- Sequence counters must be updated ONLY after full verification. Never update state on a failed message.
- Sort fetched messages by sequence number ascending before processing to avoid the offline-recipient replay-rejection bug.
- The project will be graded on: application choice, security analysis depth, design validity, implementation correctness, and presentation quality.

---

## HOW TO USE THIS PROMPT

Tell me which phase to work on. For example:
- "Build Phase 1" — I will create crypto.py
- "Build Phase 2" — I will create state.py
- "Build Phases 1-3" — I will create the core modules
- "Build Phase 8" — I will create tests

I will build each phase completely, with proper error handling, type hints, and docstrings, before moving to the next. After each phase, review the code and tell me if you want changes before proceeding.

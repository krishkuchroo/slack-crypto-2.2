# Presentation Script — E2E Encrypted Slack Channel
## NYU CS6903/4783 Applied Cryptography, Spring 2026 — Project 2.2
### Total Runtime: ~12 minutes

---

## PART 1: Introduction (1.5 min)

**[SLIDE: Title slide — show school IDs]**

> Hi everyone. Today we're presenting our Project 2.2 implementation — an end-to-end encrypted group messaging system built on top of Slack.
>
> The core idea is simple: Slack is treated as an **untrusted transport relay**. Every message is encrypted, signed, and verified locally on the sender and receiver's machines. Slack — including workspace administrators — never sees plaintext content. Even if TLS is compromised, our encryption remains intact because it operates at the application layer, completely independent of the transport.
>
> This is NOT just "TLS is good enough." TLS terminates at Slack's load balancer. After that, Slack has full access to plaintext. Our system ensures security holds across the **entire** communication path — from the sending device to the receiving device.

---

## PART 2: Architecture Overview (2 min)

**[SLIDE: Show the module diagram / repo structure]**

> The project is organized into five Python modules, each with strict separation of concerns:

> **crypto.py** handles all cryptographic operations — key generation, encryption, decryption, signing, verification, and key wrapping. This module has zero Slack API calls and zero side effects. It's a pure crypto library.

> **state.py** manages replay prevention through monotonic sequence counters and tracks group key state in JSON files. An important design detail: we use separate namespaces for send-side and receive-side counters — `send:alice` vs `recv:alice` — so the sender and receiver can coexist on the same machine without false replay detections.

> **slack_interface.py** is the transport layer — it only does two things: post a JSON blob to Slack and fetch JSON blobs from Slack. Zero cryptography in this file.

> **padding.py** provides optional fixed-size message padding to defeat traffic analysis. Uses a 4-byte length prefix scheme instead of PKCS7, because PKCS7 is limited to 255-byte block sizes.

> **client.py** is the CLI entry point — it wires everything together with 10 argparse subcommands.

---

## PART 3: Cryptographic Design (2.5 min)

**[SLIDE: Table of primitives]**

> Let's walk through our primitive selection and why we chose each one.

> **AES-256-GCM** for symmetric encryption. We chose GCM over CBC because GCM provides authenticated encryption in a single primitive — the 16-byte GCM tag covers both the ciphertext AND the Additional Authenticated Data. With CBC, you'd need to bolt on a separate HMAC, which introduces the risk of MAC-then-encrypt vs encrypt-then-MAC ordering bugs.

> **Ed25519** for digital signatures. This is a deterministic signature scheme — it doesn't require a per-signature random nonce. This matters because with ECDSA, if the nonce is ever reused or predictable, the private key can be fully recovered. This happened to Sony's PS3 code signing. Ed25519 eliminates this entire class of vulnerability.

> **X25519 ECDH** for key agreement — 32-byte keys at the 128-bit security level. RSA would need 3072-bit keys for equivalent security.

> **HKDF-SHA256** for key derivation. The raw X25519 shared secret is NOT uniformly distributed — it's a point on a curve. HKDF extracts entropy and expands it into a key indistinguishable from random. We use the channel_id as the HKDF info parameter for domain separation — same key pair in two different channels produces two different derived keys.

**[SLIDE: Sign ciphertext, not plaintext]**

> A critical design decision: we sign the **ciphertext**, not the plaintext. If we signed the plaintext, an attacker could strip the signature, re-encrypt the same content under a different key, and reattach the original valid signature. By signing the ciphertext, the signature is bound to the specific encrypted object.

> The signed blob is a SHA-256 digest of: ciphertext, IV, sender_id, sequence number, timestamp, and channel_id — concatenated with null-byte separators to prevent field confusion attacks.

---

## PART 4: Message Pipeline (1.5 min)

**[SLIDE: Send and receive pipeline diagram]**

> Here's how a message flows through the system.

> **Sending:** Alice loads her Ed25519 private key and the group AES key. She encodes her message as UTF-8, computes the next sequence number, generates an ISO-8601 timestamp, builds the AAD dictionary — that's version, channel_id, sender_id, sequence, and timestamp serialized as sorted JSON — then encrypts with AES-256-GCM using a fresh 96-bit random IV. She builds the signed blob, signs it with Ed25519, packages everything as a JSON payload with base64-encoded fields, and posts it to Slack.

> **Receiving:** Bob fetches messages from Slack, sorts them by sequence number ascending — this is critical to prevent the offline-recipient bug where the first message updates the counter and all older messages get rejected. For each message: first replay check, then Ed25519 signature verification, then AES-GCM decryption. Sequence counters are updated ONLY after both signature and GCM tag pass. A failed message never advances the counter.

> The AAD fields — version, channel_id, sender_id, sequence, and timestamp — are authenticated but not encrypted. This lets recipients inspect metadata for routing before doing the more expensive decryption, while still detecting any tampering.

---

## PART 5: Live Demo — Normal Flow (1 min)

**[TERMINAL: Run live commands]**

> Let me show you this working against a real Slack workspace.

```
python client.py keygen --name alice
python client.py keygen --name bob
python client.py fingerprint --name alice
python client.py init-channel --channel all-testing-ground --admin alice --members bob
python client.py post --channel all-testing-ground --sender alice --message 'Isolate host 10.0.0.5 immediately - compromised by APT29'
```

> If you look at the Slack channel right now, you'll see an opaque JSON blob — base64-encoded ciphertext, IV, signature. No plaintext visible.

```
python client.py fetch --channel all-testing-ground --receiver bob
```

> Bob successfully decrypts: "Isolate host 10.0.0.5 immediately - compromised by APT29"

---

## PART 6: Live Demo — Attack Scenarios (3 min)

### Demo 6a: Spoofing Attack

**[TERMINAL]**

> Now let's simulate an attacker. Mallory generates her own keys and sends a message claiming to be alice — she signs with her own Ed25519 key but sets sender_id to 'alice'.

```
python client.py keygen --name mallory
python client.py post --channel all-testing-ground --sender mallory --spoof-sender-id alice --message 'Shut down the firewall NOW'
python client.py fetch --channel all-testing-ground --receiver bob
```

> Output: **[SPOOF] Signature invalid for message from alice**. Bob loads alice's real public key, computes the expected signed blob, and Ed25519 verification fails because mallory's signature doesn't match alice's key.

### Demo 6b: Replay Attack

**[TERMINAL]**

> Next, replay. We re-post alice's original message with sequence number 1.

```
python client.py replay --channel all-testing-ground --seq 1
python client.py fetch --channel all-testing-ground --receiver bob
```

> Output: **[REPLAY] Rejected message from alice seq=1 (last accepted: 1)**. The monotonic counter per sender catches it — any message with seq less than or equal to the last accepted value is rejected.

### Demo 6c: Key Lifecycle (Add + Revoke)

**[TERMINAL]**

> Finally, key lifecycle. We add carol to the channel, verify she can read messages, then revoke her.

```
python client.py keygen --name carol
python client.py addmember --channel all-testing-ground --admin alice --member carol
python client.py post --channel all-testing-ground --sender alice --message 'Welcome carol'
python client.py fetch --channel all-testing-ground --receiver carol
```

> Carol successfully decrypts. Now we revoke her:

```
python client.py revoke --channel all-testing-ground --admin alice --member carol
python client.py post --channel all-testing-ground --sender alice --message 'Carol cannot read this'
python client.py fetch --channel all-testing-ground --receiver carol
```

> Output: **[ERROR] Cannot decrypt: 'carol' is not a member of the current key**. Revocation generates a new group AES key and wraps it for everyone except carol. Her keys are moved to `keys/revoked/`. She can never decrypt messages sent after her revocation.

---

## PART 7: Extended Security Analysis (1.5 min)

**[SLIDE: Extended threat model table]**

> Beyond the four mandatory attacks, we analyzed several extended scenarios.

> **Slack as an active adversary.** A workspace admin can observe metadata — who posted, when, message sizes. Our optional `--pad` flag pads messages to 512-byte blocks to defeat size-based analysis. The admin can delete messages — we detect this with `--check-gaps` which compares expected vs received sequence numbers. The admin can inject messages — they fail Ed25519 verification. The admin can reorder messages — we sort by sequence number before processing.

> **Compromised group member.** If a signing key is compromised, the attacker can impersonate that member until key rotation. If an X25519 key is compromised, the attacker can derive the group key for all past messages — we don't have forward secrecy. That would require a ratcheting protocol like Signal's Double Ratchet, which is beyond the primitives covered through Lecture 6/7. We document this as a known limitation.

> **Combined attacks.** Replay plus spoofing fails because sender_id is in both the signed blob and the AAD. Modification plus replay is caught by GCM tag and sequence counter independently.

> **Key distribution MITM.** If an attacker substitutes public keys during the out-of-band exchange, the system fails silently. Our `fingerprint` command outputs SHA-256 hashes for manual verification over a trusted channel.

---

## PART 8: Testing & Wrap-up (1 min)

**[SLIDE: Test results]**

> We have 51 tests across three test files — 22 unit tests for crypto.py, 12 for state.py, and 17 integration tests that simulate the full pipeline with a mock Slack channel. All tests pass.

```
python -m unittest discover -s tests -v
# Ran 51 tests in 0.5s — OK
```

> **Known limitations** we documented: no per-message forward secrecy, metadata not hidden, no key transparency, single admin trust, and no message ordering guarantee.

> All cryptographic operations use the `cryptography` library (PyCA/OpenSSL). No custom crypto primitives were implemented.

> Thank you. Any questions?

---

## Quick Reference — Demo Commands Cheat Sheet

```bash
# Keygen
python client.py keygen --name alice
python client.py keygen --name bob

# Fingerprints
python client.py fingerprint --name alice

# Init channel
python client.py init-channel --channel all-testing-ground --admin alice --members bob

# Normal post + fetch
python client.py post --channel all-testing-ground --sender alice --message 'Isolate host 10.0.0.5'
python client.py fetch --channel all-testing-ground --receiver bob

# Spoofing demo
python client.py keygen --name mallory
python client.py post --channel all-testing-ground --sender mallory --spoof-sender-id alice --message 'Fake message'
python client.py fetch --channel all-testing-ground --receiver bob

# Replay demo
python client.py replay --channel all-testing-ground --seq 1
python client.py fetch --channel all-testing-ground --receiver bob

# Key lifecycle
python client.py keygen --name carol
python client.py addmember --channel all-testing-ground --admin alice --member carol
python client.py revoke --channel all-testing-ground --admin alice --member carol

# Padded message
python client.py post --channel all-testing-ground --sender alice --message 'short' --pad

# Gap detection
python client.py fetch --channel all-testing-ground --receiver bob --check-gaps
```

# Encrypted Slack Channel for Security Incident Response

### NYU CS6903/4783 Applied Cryptography, Spring 2026 -- Project 2.2

A Python command-line tool that provides end-to-end encrypted group messaging over Slack. Slack is treated as an untrusted transport relay. All cryptographic operations happen on sender and recipient machines. Slack (including workspace administrators) never sees plaintext. Security holds across the entire communication path from sending device to receiving device, independent of TLS or any transport-layer protection.

---

## Threat Model

The attacker has full Slack workspace administrator access. This means they can read all channel metadata (who posted, when, message ordering, message sizes), delete or reorder messages, and inject new JSON blobs into channels. TLS protects data between client devices and Slack servers, but TLS terminates at Slack's load balancer, giving Slack access to plaintext message content. TLS is therefore encryption in transit, not end-to-end encryption. Even if TLS were compromised via a rogue CA certificate, our cryptographic layer remains intact because it operates at the application level, entirely on the user's machine. The plaintext never leaves the user's device unencrypted.

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Create a Slack bot

1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app.
2. Under **OAuth & Permissions**, add the following Bot Token Scopes: `channels:history`, `channels:read`, `chat:write`.
3. Install the app to your workspace and copy the **Bot User OAuth Token**.
4. Create a channel for testing (e.g., `#incident-2026`) and invite the bot to it.

### 3. Configure the token

```bash
cp .env.example .env
# Edit .env and paste your Bot User OAuth Token
```

### 4. Generate keypairs

```bash
python client.py keygen --name alice
python client.py keygen --name bob
```

### 5. Verify fingerprints

Before initializing a channel, verify public key fingerprints over a trusted out-of-band channel (in person, phone call). This prevents man-in-the-middle key substitution.

```bash
python client.py fingerprint --name alice
python client.py fingerprint --name bob
```

---

## Quick Start

```bash
# Initialize an encrypted channel (alice is admin, bob is a member)
python client.py init-channel --channel incident-2026 --admin alice --members bob

# Alice sends an encrypted message
python client.py post --channel incident-2026 --sender alice --message 'Isolate host 10.0.0.5 immediately'

# Bob fetches and decrypts
python client.py fetch --channel incident-2026 --receiver bob
```

---

## Security Properties

| Property | Mechanism | Attack Covered |
|----------|-----------|----------------|
| Confidentiality | AES-256-GCM encryption | Data eavesdropping |
| Integrity | GCM authentication tag + AAD | Data modification |
| Authentication | Ed25519 digital signature over ciphertext | Originator spoofing |
| Replay prevention | Monotonic sequence counter per sender | Data replay |
| Key agreement | X25519 ECDH + HKDF-SHA256 | Secure key derivation |
| Key distribution | Per-member wrapping via ECDH + AES-GCM | Group key confidentiality |
| Key rotation | Admin-initiated re-keying with member exclusion | Forward secrecy (partial), revocation |
| Key trust | SHA-256 fingerprint verification | MITM during key exchange |
| Traffic analysis mitigation | Optional fixed-size message padding | Metadata leakage (partial) |
| Message gap detection | Sequence gap analysis on fetch | Selective deletion by service provider |
| TLS independence | Application-layer encryption | End-to-end (not just in-transit) |

---

## Extended Threat Analysis

**Service Provider Attacks (Slack as Active Adversary).** A Slack admin can read all channel metadata, delete messages selectively, reorder messages in channel history, and inject new JSON blobs. Metadata exposure (who posted, when, message sizes) is a traffic analysis vector that encryption does not hide. Deletion causes denial of service detectable via sequence gap analysis (`--check-gaps`). Reordering is detected by the monotonic sequence counter. Injected messages fail Ed25519 signature verification because the admin does not possess any member's signing key.

**Compromised Group Member.** If a member's Ed25519 signing key is compromised, the attacker can impersonate that member until key rotation excludes them. If a member's X25519 private key is compromised, the attacker can derive the group AES key for any channel where that member participated, including past messages (no forward secrecy). Periodic group key rotation limits the window of exposure. Forward secrecy per message would require a ratcheting protocol (e.g., Signal's Double Ratchet), which is beyond the primitives covered through Lecture 6/7.

**Combined Attacks.** Replay plus spoofing (attacker captures a valid message, modifies sender_id, replays it) is prevented because sender_id is included in both the signed blob and the AAD. Modification plus replay is caught by GCM tag verification and sequence counter. Metadata leakage combined with traffic analysis (distinguishing short acks from long reports by ciphertext size) is mitigated by optional message padding (`--pad`).

**Key Distribution Attacks.** If the out-of-band key exchange is compromised by a man-in-the-middle who substitutes public keys, the entire system fails silently. The fingerprint verification protocol detects this: members compare SHA-256 hashes of their public keys over a separate trusted channel before proceeding.

---

## Design Decisions

| Decision | Justification |
|----------|---------------|
| AES-256-GCM over AES-CBC | GCM provides authenticated encryption in one primitive. CBC requires a separate HMAC for integrity. |
| Ed25519 over ECDSA | Ed25519 is deterministic (no per-signature random nonce). ECDSA nonce reuse leaks the private key entirely. |
| Sign ciphertext, not plaintext | Signing plaintext allows an attacker to strip the signature, re-encrypt under a different key, and reattach the original valid signature. |
| Sequence counter over timestamp | Timestamps are unreliable across machines with clock skew. Monotonic counters provide a strict ordering per sender. |
| X25519 over RSA | At 128-bit security level, X25519 uses 32-byte keys. RSA equivalent requires 3072-bit keys. |
| HKDF over raw DH output | Raw X25519 output is not uniformly distributed. HKDF extracts and expands it into a uniformly random key. |
| AAD for message headers | Version, channel_id, sender_id, sequence, and timestamp are authenticated (tamper-evident) but left unencrypted so recipients can route and filter before decryption. |

---

## Key Trust Model

Public keys are exchanged through a channel that provides authenticity (but not necessarily confidentiality): in-person USB exchange, a phone call where both parties verify fingerprints, or a trusted internal directory. The `fingerprint` command outputs the SHA-256 hash of each public key in colon-separated hex format. Members verify fingerprints before proceeding with channel initialization.

If fingerprints are not verified, the system still functions, but a man-in-the-middle who substitutes public keys during exchange can decrypt all messages, sign messages as any party, and remain undetected. This is a prerequisite trust assumption, not a system limitation.

---

## Known Limitations

1. **No forward secrecy per message.** A compromised group key exposes all messages encrypted under that key. Per-message forward secrecy requires a ratcheting protocol, which is beyond Lecture 6/7 primitives.
2. **Metadata not hidden.** Slack sees sender timing, message sizes, and channel activity patterns. Optional padding mitigates size analysis but not timing.
3. **No key transparency.** There is no automated mechanism to detect if Slack or a MITM has substituted public keys. Fingerprint verification is manual.
4. **Single admin trust.** The channel admin generates and distributes the group key. A compromised admin compromises the entire channel.
5. **No message ordering guarantee.** Slack may reorder messages. The sequence counter detects this but does not enforce a specific delivery order.

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `python client.py keygen --name alice` | Generate X25519 and Ed25519 keypairs |
| `python client.py fingerprint --name alice` | Print SHA-256 fingerprints of public keys |
| `python client.py init-channel --channel C --admin alice --members bob,carol` | Create channel, generate and distribute group key |
| `python client.py post --channel C --sender alice --message 'text' [--pad]` | Encrypt and post (optional padding) |
| `python client.py fetch --channel C --receiver bob --limit 20 [--check-gaps]` | Fetch, verify, decrypt (optional gap detection) |
| `python client.py addmember --channel C --admin alice --member dave` | Wrap group key for new member |
| `python client.py revoke --channel C --admin alice --member carol` | Rotate key excluding revoked member |
| `python client.py rotate --channel C --admin alice` | Generate and redistribute new group AES key |
| `python client.py verify --channel C --receiver bob` | Fetch without decrypting (signature check only) |
| `python client.py replay --channel C --seq 1` | Re-post an old message (demo attack simulation) |

---

## Libraries

This project uses the `cryptography` library (PyCA), which wraps OpenSSL, for all cryptographic primitives. No custom cryptographic implementations are used. The `slack_sdk` library handles Slack API communication, and `python-dotenv` manages environment variable loading.

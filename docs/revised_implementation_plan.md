# NYU CS6903/4783 — Applied Cryptography | Spring 2026
# Project 2.2 — Revised Implementation Plan
# Encrypted Slack Channel for Security Incident Response

---

## 1. Project Overview (Unchanged)

Command-line Python tool providing end-to-end encrypted group messaging over Slack. Slack is treated as an untrusted transport relay. All cryptographic operations happen on sender and recipient machines. Slack sees only opaque JSON ciphertext blobs.

---

## 2. Gap Analysis and Revisions

This revised plan addresses seven gaps identified in the original implementation document.

---

### GAP 1 — Expanded Security Analysis (Grading Criterion 2)

**Problem:** The original document covered the four mandatory attacks but did not analyze variations, combinations, or attacks from other parties (e.g., service providers). The rubric explicitly requires this expanded analysis.

**Revision — Add Section 3A: Extended Threat Model**

The revised document will include a dedicated section analyzing the following attack categories beyond the four core attacks:

**2a. Slack as an Active Adversary (Service Provider Attacks)**

- Slack admin with full workspace access can read all channel metadata: who posted, when, message ordering, message sizes. This is a traffic analysis vector. The crypto layer does not hide metadata.
- Slack admin can delete messages selectively, causing denial of service. The recipient will simply never see the message. Mitigation: recipients can maintain a local log of expected sequence numbers and flag gaps. Implementation adds a `--check-gaps` flag to the fetch command.
- Slack admin can reorder messages in the channel history. Mitigation: the monotonic sequence counter per sender detects this — any out-of-order delivery is flagged. Messages are processed in sequence-number order, not channel order.
- Slack admin can inject entirely new JSON blobs into the channel. Mitigation: any injected message will fail Ed25519 signature verification because the admin does not possess any member's signing key.

**2b. Compromised Group Member**

- If a member's Ed25519 signing key is compromised, the attacker can impersonate that member. Mitigation: key rotation via the `rotate` command generates a new group key and new signing keypairs. The compromised member is excluded from the new key distribution.
- If a member's X25519 private key is compromised, the attacker can derive the group AES key for any channel where that member participated. This means past messages encrypted under that group key are also compromised (no forward secrecy). Mitigation: periodic group key rotation limits the window of exposure. Document this as a known limitation and note that achieving forward secrecy would require a ratcheting protocol (e.g., Signal's Double Ratchet), which is beyond the scope of primitives covered through Lecture 6/7.

**2c. Combined Attacks**

- Replay + Spoofing: attacker captures a valid message, modifies the sender_id field, and replays it. Mitigation: the sender_id is included in both the signed blob and the AAD. Changing sender_id breaks the GCM tag. Replaying with the original sender_id is caught by the sequence counter.
- Modification + Replay: attacker modifies ciphertext and replays an old message. Mitigation: GCM tag detects modification; sequence counter detects replay. Both checks must pass.
- Metadata leakage + traffic analysis: even with encryption, message sizes and timing patterns can reveal information (e.g., an observer can distinguish short acknowledgments from long incident reports). Mitigation: optional message padding to a fixed block size (512 bytes). Implementation adds a `--pad` flag to the post command.

**2d. Key Distribution Channel Attacks**

- If the out-of-band key exchange is compromised (man-in-the-middle substitutes public keys), the entire system fails silently. Mitigation: public key fingerprint verification. Implementation adds a `fingerprint` CLI command that outputs the SHA-256 hash of each public key. Members verify fingerprints over a separate trusted channel (in-person, phone call). See Gap 4 below.

---

### GAP 2 — Full Group Key Distribution Lifecycle (Design Completeness)

**Problem:** The original document hand-waved key distribution with a comment saying members store their own unwrapped copy. The actual lifecycle was not documented.

**Revision — Add Section 4A: Group Key Lifecycle**

**Phase 1: Channel Initialization (performed by channel admin)**

```
python client.py init-channel --channel incident-2026 --admin alice \
    --members bob,carol
```

Steps executed internally:
1. Admin generates a random 256-bit AES group key: `os.urandom(32)`
2. For each member (including admin), admin performs ECDH with the member's X25519 public key, derives a wrapping key via HKDF with info = `channel_id + ':wrap'`, and encrypts the group key with AES-256-GCM using the wrapping key.
3. The wrapped group keys are stored in `state/group_keys.json` as a mapping: `channel_id -> member_id -> {ciphertext, iv}`.
4. Each member's wrapped key blob is posted to a designated Slack channel (or delivered out-of-band). The member runs `unwrap` locally to obtain the group AES key.

**Phase 2: Member Addition**

```
python client.py addmember --channel incident-2026 --admin alice --member dave
```

Steps:
1. Admin loads the plaintext group key from their local state.
2. Admin wraps the group key for the new member using `wrap_group_key()`.
3. Wrapped blob is delivered to the new member.
4. New member runs unwrap to obtain the group key and stores it locally.

**Phase 3: Key Rotation**

```
python client.py rotate --channel incident-2026 --admin alice
```

Steps:
1. Admin generates a new random 256-bit AES group key.
2. Admin wraps the new key for every current member (excluding any revoked members).
3. New wrapped blobs are distributed. Old group key is deleted from local state.
4. Messages encrypted under the old key remain readable only if the old key was archived (optional `--archive-old-key` flag). By default, old keys are discarded.

**Phase 4: Member Revocation**

```
python client.py revoke --channel incident-2026 --admin alice --member carol
```

Steps:
1. Admin performs key rotation (Phase 3) but excludes the revoked member from the new wrapped key distribution.
2. Revoked member's public keys are moved to a `revoked/` directory. Any message signed with a revoked key after the rotation timestamp is rejected.

**Implementation Note:** `state/group_keys.json` schema change:

```json
{
  "incident-2026": {
    "current_key_id": "key-20260327-001",
    "keys": {
      "key-20260327-001": {
        "created_at": "2026-03-27T14:00:00Z",
        "created_by": "alice",
        "members": {
          "alice": {"ciphertext": "...", "iv": "..."},
          "bob": {"ciphertext": "...", "iv": "..."}
        }
      }
    }
  }
}
```

---

### GAP 3 — Explicit TLS Distinction (Requirement Compliance)

**Problem:** The guidelines explicitly state not to use TLS as a black box. The original document mentions this briefly but does not dedicate a clear section to it.

**Revision — Add Section 2B: Why TLS Is Insufficient**

The revised document will include a dedicated subsection explaining:

- TLS protects data between the client device and the Slack server. Once the TLS session terminates at Slack's load balancer, Slack has access to plaintext message content. This is encryption in transit, not end-to-end encryption.
- Our threat model assumes the attacker has Slack workspace admin access. TLS does not protect against this attacker — they can read any message stored on Slack's servers.
- Our cryptographic layer operates at the application level, entirely on the user's machine. The plaintext never leaves the user's device unencrypted. Slack only ever receives and stores the ciphertext blob.
- Even if TLS were compromised (e.g., via a rogue CA certificate), our encryption remains intact because it is independent of the transport layer.
- This satisfies the project requirement: security holds "across the entire communication path from the sending device to the receiving device, including the link connecting the device to the data processing application."

---

### GAP 4 — Public Key Trust Model (Security Analysis Completeness)

**Problem:** The original document said "exchange public keys out of band" with no further specification. If an attacker substitutes their public key during this exchange, all security guarantees collapse.

**Revision — Add Section 3B: Key Trust Model and Fingerprint Verification**

**Trust Assumption:** Public keys are exchanged through a channel that provides authenticity (but not necessarily confidentiality). Examples: in-person USB exchange, a phone call where both parties verify fingerprints, or a trusted internal directory.

**Fingerprint Command:**

```
python client.py fingerprint --name alice
```

Output:
```
Alice X25519 public key fingerprint:
  SHA-256: 4a:bf:c3:d9:12:...  (truncated to 32 hex chars for readability)

Alice Ed25519 public key fingerprint:
  SHA-256: 7e:01:a8:f3:55:...
```

**Verification Protocol:**
1. Alice and Bob generate their keypairs locally.
2. They meet in person (or call each other) and read their fingerprints aloud.
3. Each party verifies the fingerprint matches the public key file they received.
4. Only after verification do they proceed with channel initialization.

**Implementation in crypto.py:**

```python
import hashlib

def fingerprint(public_key_path: str) -> str:
    with open(public_key_path, 'rb') as f:
        key_bytes = f.read()
    digest = hashlib.sha256(key_bytes).hexdigest()
    return ':'.join(digest[i:i+2] for i in range(0, len(digest), 2))
```

**What if fingerprints are not verified?** The system still works, but a man-in-the-middle who substitutes public keys during exchange can decrypt all messages, sign messages as any party, and remain undetected. This is documented as a prerequisite trust assumption, not a system limitation — it is analogous to how SSH's trust-on-first-use model works.

---

### GAP 5 — Submission Formatting Compliance (Overall Guidelines)

**Problem:** The overall guidelines specify exact file naming conventions, a presentation PDF, and a 10-15 minute video. These are not addressed in the implementation document.

**Revision — Add Section 13: Submission Checklist**

Deliverables:
1. **Presentation PDF:** `<last-names>-applied-cryptography-spring-26-project-type-2.2-presentation.pdf`
2. **Software ZIP:** `<last-names>-applied-cryptography-spring-26-project-type-2.2-software.zip`
   - Contains: `<last-names>-source/` (all .py files, requirements.txt, README.md)
   - Contains: `<last-names>-presentation/` (the .pptx source file)
   - Contains: `keys/` directory with sample keypairs for demo
   - Contains: `demo/` directory with all demo shell scripts
3. **Video:** 10-15 minute presentation recorded via NYU Stream. Each team member presents approximately equal time and shows their school ID at the start. Video includes live demo of all five scenarios.
4. **Quiz Submission:** Team name, member names/emails, project type (2.2), project title, video link, PDF attachment, ZIP attachment.

---

### GAP 6 — Team Member Contribution Breakdown (Overall Guidelines)

**Problem:** The guidelines require detailing which member did what task or percentage. This was missing.

**Revision — Add Section 14: Work Distribution**

Template to be filled in before submission:

| Task | Member(s) | Percentage |
|------|-----------|------------|
| Cryptographic design (crypto.py) | | |
| Slack integration (slack_interface.py) | | |
| Replay prevention (state.py) | | |
| CLI and orchestration (client.py) | | |
| Security analysis and threat model | | |
| Key distribution lifecycle design | | |
| Demo scripts and testing | | |
| Presentation slides | | |
| Video recording and editing | | |
| README and documentation | | |

---

### GAP 7 — Sequence Counter Edge Case (Technical Robustness)

**Problem:** If a recipient goes offline and misses messages, then comes back, the fetch command processes messages newest-first. The first accepted message updates the sequence counter, causing all older missed messages to be rejected as replays.

**Revision — Modify fetch logic in client.py**

Change: Sort fetched messages by sequence number in ascending order before processing.

```python
def cmd_fetch(args):
    messages = slack_interface.fetch_messages(args.channel, args.limit)
    
    # Sort by sequence number ascending to process in order
    messages.sort(key=lambda m: m.get('sequence', 0))
    
    for payload in messages:
        # ... existing verification logic ...
```

Additionally, add gap detection:

```python
    # After processing all messages, check for gaps
    if args.check_gaps:
        expected = set(range(last_known_seq + 1, max_seen_seq + 1))
        received = set(accepted_sequences)
        missing = expected - received
        if missing:
            print(f'[WARNING] Missing sequence numbers: {sorted(missing)}')
            print(f'  Possible message deletion by Slack admin or network loss.')
```

---

## 3. Revised Repository Structure

```
project-2.2/
├── client.py              # CLI entry point — all commands
├── crypto.py              # All cryptographic operations + fingerprint
├── slack_interface.py     # Slack API calls — post and fetch only
├── state.py               # Replay prevention + key state management
├── padding.py             # Optional message padding (traffic analysis mitigation)
├── requirements.txt       # Python dependencies
├── README.md              # Setup, run instructions, security properties
├── .env                   # SLACK_BOT_TOKEN (not committed to repo)
│
├── keys/
│   ├── alice_x25519_private.pem
│   ├── alice_x25519_public.pem
│   ├── alice_ed25519_private.pem
│   ├── alice_ed25519_public.pem
│   ├── <member>_*.pem
│   └── revoked/           # Revoked member keys moved here
│
├── state/
│   ├── sequence_state.json
│   └── group_keys.json    # Revised schema with key_id and lifecycle
│
└── demo/
    ├── demo_normal.sh
    ├── demo_tamper.sh
    ├── demo_spoof.sh
    ├── demo_replay.sh
    ├── demo_key_rotation.sh    # NEW: demonstrates key lifecycle
    └── demo_fingerprint.sh     # NEW: demonstrates key verification
```

---

## 4. Revised CLI Reference

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
| `python client.py verify --channel C --receiver bob` | Fetch without decrypting — signature check only |

---

## 5. Revised Demo Script (6 Scenarios)

**Scenario 1 — Normal Flow** (unchanged)

**Scenario 2 — Modification Detected** (unchanged)

**Scenario 3 — Spoofing Rejected** (unchanged)

**Scenario 4 — Replay Rejected** (unchanged)

**Scenario 5 — Key Lifecycle (NEW)**
```bash
# Initialize channel with alice as admin, bob and carol as members
python client.py init-channel --channel incident-2026 --admin alice --members bob,carol

# Show group_keys.json — all three members have wrapped keys
cat state/group_keys.json

# Alice posts a message, bob decrypts successfully
python client.py post --channel incident-2026 --sender alice --message 'Initial key works'
python client.py fetch --channel incident-2026 --receiver bob

# Rotate key, excluding carol (simulating revocation)
python client.py revoke --channel incident-2026 --admin alice --member carol

# Alice posts with new key, bob decrypts, carol cannot
python client.py post --channel incident-2026 --sender alice --message 'After rotation'
python client.py fetch --channel incident-2026 --receiver bob
python client.py fetch --channel incident-2026 --receiver carol
# Expected: carol sees [ERROR] Cannot decrypt — not a member of current key
```

**Scenario 6 — Fingerprint Verification (NEW)**
```bash
python client.py fingerprint --name alice
python client.py fingerprint --name bob
# Show fingerprints side by side, explain the verification protocol
```

---

## 6. Updated Security Properties Summary

| Property | Mechanism | Covers |
|----------|-----------|--------|
| Confidentiality | AES-256-GCM | Data eavesdropping |
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

## 7. Known Limitations (Documented for Transparency)

1. **No forward secrecy per message.** A compromised group key exposes all messages encrypted under that key. Achieving per-message forward secrecy requires a ratcheting protocol, which is beyond Lecture 6/7 primitives.
2. **Metadata not hidden.** Slack sees sender timing, message sizes, and channel activity patterns. The optional padding mitigates size analysis but not timing.
3. **No key transparency.** There is no automated mechanism to detect if Slack (or a MITM) has substituted public keys. Fingerprint verification is manual.
4. **Single admin trust.** The channel admin generates and distributes the group key. A compromised admin compromises the entire channel. Multi-admin threshold schemes are out of scope.
5. **No message ordering guarantee.** Slack may reorder messages. The sequence counter detects this but does not enforce a specific delivery order.

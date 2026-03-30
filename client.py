"""
client.py -- CLI entry point for E2E encrypted Slack messaging.
NYU CS6903/4783 Project 2.2

Uses argparse with subcommands. Wires together crypto.py, slack_interface.py,
state.py, and padding.py. All cryptographic exceptions are caught and
translated into user-friendly CLI output.
"""

import argparse
import base64
import json
import os
import shutil
import sys
from datetime import datetime, timezone

import crypto
import padding as pad_module
import slack_interface
import state


KEYS_DIR = "keys"
REVOKED_DIR = os.path.join(KEYS_DIR, "revoked")


def _ensure_dirs() -> None:
    """Create keys/ and state/ directories if they do not exist."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(REVOKED_DIR, exist_ok=True)
    os.makedirs("state", exist_ok=True)


def _key_path(name: str, key_type: str, access: str) -> str:
    """Build a key file path.

    Args:
        name: User name (e.g. "alice").
        key_type: "x25519" or "ed25519".
        access: "private" or "public".

    Returns:
        Path string like "keys/alice_x25519_private.pem".
    """
    return os.path.join(KEYS_DIR, f"{name}_{key_type}_{access}.pem")


# ---------------------------------------------------------------------------
# Subcommand: keygen
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate X25519 and Ed25519 keypairs for a user."""
    _ensure_dirs()
    name = args.name

    # X25519
    x_priv, x_pub = crypto.generate_x25519_keypair()
    crypto.save_private_key(x_priv, _key_path(name, "x25519", "private"))
    crypto.save_public_key(x_pub, _key_path(name, "x25519", "public"))

    # Ed25519
    ed_priv, ed_pub = crypto.generate_ed25519_keypair()
    crypto.save_private_key(ed_priv, _key_path(name, "ed25519", "private"))
    crypto.save_public_key(ed_pub, _key_path(name, "ed25519", "public"))

    print(f"[OK] Generated keypairs for '{name}' in {KEYS_DIR}/")
    print(f"  X25519:  {_key_path(name, 'x25519', 'private')}")
    print(f"           {_key_path(name, 'x25519', 'public')}")
    print(f"  Ed25519: {_key_path(name, 'ed25519', 'private')}")
    print(f"           {_key_path(name, 'ed25519', 'public')}")


# ---------------------------------------------------------------------------
# Subcommand: fingerprint
# ---------------------------------------------------------------------------

def cmd_fingerprint(args: argparse.Namespace) -> None:
    """Print SHA-256 fingerprints of a user's public keys."""
    name = args.name

    x_pub_path = _key_path(name, "x25519", "public")
    ed_pub_path = _key_path(name, "ed25519", "public")

    if not os.path.exists(x_pub_path) or not os.path.exists(ed_pub_path):
        print(f"[ERROR] Public keys for '{name}' not found. Run keygen first.")
        sys.exit(1)

    x_fp = crypto.fingerprint(x_pub_path)
    ed_fp = crypto.fingerprint(ed_pub_path)

    print(f"{name} X25519 public key fingerprint:")
    print(f"  SHA-256: {x_fp}")
    print(f"{name} Ed25519 public key fingerprint:")
    print(f"  SHA-256: {ed_fp}")


# ---------------------------------------------------------------------------
# Subcommand: init-channel
# ---------------------------------------------------------------------------

def cmd_init_channel(args: argparse.Namespace) -> None:
    """Create a channel, generate a group AES key, wrap for each member."""
    _ensure_dirs()
    channel = args.channel
    admin = args.admin
    members = [m.strip() for m in args.members.split(",")]

    # Include admin in the member list
    all_members = [admin] + [m for m in members if m != admin]

    # Generate random 256-bit group AES key
    group_key = os.urandom(32)
    group_key_hex = group_key.hex()

    # Load admin's X25519 private key
    admin_x_priv = crypto.load_x25519_private(
        _key_path(admin, "x25519", "private")
    )

    # Wrap group key for each member
    key_id = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    wrapped_keys = {}
    for member in all_members:
        member_x_pub = crypto.load_x25519_public(
            _key_path(member, "x25519", "public")
        )
        wrapped = crypto.wrap_group_key(
            group_key, member_x_pub, admin_x_priv, channel
        )
        wrapped_keys[member] = wrapped

    # Store in group_keys.json
    state.init_channel(channel, admin, key_id, wrapped_keys, group_key_hex)

    print(f"[OK] Channel '{channel}' initialized")
    print(f"  Admin: {admin}")
    print(f"  Members: {', '.join(all_members)}")
    print(f"  Key ID: {key_id}")
    print(f"  Group key stored in state/group_keys.json")


# ---------------------------------------------------------------------------
# Subcommand: post
# ---------------------------------------------------------------------------

def cmd_post(args: argparse.Namespace) -> None:
    """Encrypt a message and post it to a Slack channel."""
    channel = args.channel
    sender = args.sender
    message_text = args.message
    use_padding = args.pad
    spoof_sender_id = getattr(args, "spoof_sender_id", None)

    # The sender_id that goes into the message metadata
    # (for spoofing demo: sender signs with their own key but claims
    # to be someone else)
    claimed_sender = spoof_sender_id if spoof_sender_id else sender

    # Load sender's keys
    ed_priv = crypto.load_ed25519_private(
        _key_path(sender, "ed25519", "private")
    )

    # Load group AES key from state
    try:
        key_entry = state.get_group_key(channel, sender)
    except KeyError:
        # If spoofing, try loading with claimed sender
        if spoof_sender_id:
            try:
                key_entry = state.get_group_key(channel, spoof_sender_id)
            except KeyError:
                print(f"[ERROR] No group key for '{sender}' or '{spoof_sender_id}' on channel '{channel}'")
                sys.exit(1)
        else:
            print(f"[ERROR] No group key for '{sender}' on channel '{channel}'")
            sys.exit(1)

    group_key = bytes.fromhex(key_entry["plaintext_hex"])

    # Prepare plaintext
    plaintext = message_text.encode("utf-8")
    if use_padding:
        plaintext = pad_module.pad_message(plaintext)

    # Build sequence and timestamp
    sequence = state.get_next_send_seq(claimed_sender)
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build AAD
    aad_dict = {
        "version": 1,
        "channel_id": channel,
        "sender_id": claimed_sender,
        "sequence": sequence,
        "timestamp": timestamp,
    }
    aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")

    # Encrypt
    ciphertext, iv = crypto.encrypt_message(plaintext, group_key, aad)

    # Build signed blob and sign
    signed_blob = crypto.build_signed_blob(
        ciphertext, iv, claimed_sender, sequence, timestamp, channel
    )
    signature = crypto.sign_message(ed_priv, signed_blob)

    # Package as JSON for Slack
    payload = {
        "version": 1,
        "channel_id": channel,
        "sender_id": claimed_sender,
        "sequence": sequence,
        "timestamp": timestamp,
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "padded": use_padding,
    }

    # Post to Slack
    slack_interface.post_message(channel, payload)

    # Update local send sequence counter
    state.update_send_seq(claimed_sender, sequence)

    print(f"[OK] Message posted to #{channel}")
    print(f"  Sender: {claimed_sender}")
    print(f"  Sequence: {sequence}")
    print(f"  Padded: {use_padding}")
    print(f"  Ciphertext length: {len(ciphertext)} bytes")


# ---------------------------------------------------------------------------
# Subcommand: fetch
# ---------------------------------------------------------------------------

def cmd_fetch(args: argparse.Namespace) -> None:
    """Fetch, verify, and decrypt messages from a Slack channel."""
    channel = args.channel
    receiver = args.receiver
    limit = args.limit
    check_gaps = args.check_gaps

    # Load receiver's group key
    try:
        key_entry = state.get_group_key(channel, receiver)
    except KeyError:
        print(f"[ERROR] Cannot decrypt: '{receiver}' is not a member of "
              f"the current key on channel '{channel}'")
        sys.exit(1)

    group_key = bytes.fromhex(key_entry["plaintext_hex"])

    # Fetch messages from Slack
    messages = slack_interface.fetch_messages(channel, limit)

    # Sort by sequence number ascending (prevents offline-recipient bug)
    messages.sort(key=lambda m: m.get("sequence", 0))

    accepted_sequences = []
    last_known_seq = state.get_last_seq("__any__")  # track for gap detection

    for payload in messages:
        sender_id = payload.get("sender_id", "unknown")
        seq = payload.get("sequence", 0)

        # 1. Replay check
        if state.is_replay(sender_id, seq):
            print(f"[REPLAY] Rejected message from {sender_id} seq={seq} "
                  f"(last accepted: {state.get_last_seq(sender_id)})")
            continue

        # 2. Decode fields
        try:
            iv = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            signature = base64.b64decode(payload["signature"])
        except (KeyError, Exception) as e:
            print(f"[ERROR] Malformed message from {sender_id}: {e}")
            continue

        timestamp = payload.get("timestamp", "")
        channel_id = payload.get("channel_id", channel)

        # 3. Reconstruct signed blob and verify signature
        signed_blob = crypto.build_signed_blob(
            ciphertext, iv, sender_id, seq, timestamp, channel_id
        )
        try:
            sender_ed_pub = crypto.load_ed25519_public(
                _key_path(sender_id, "ed25519", "public")
            )
            crypto.verify_signature(sender_ed_pub, signed_blob, signature)
        except FileNotFoundError:
            print(f"[SPOOF] No public key found for sender '{sender_id}'")
            continue
        except Exception:
            print(f"[SPOOF] Signature invalid for message from {sender_id} "
                  f"seq={seq}")
            continue

        # 4. Reconstruct AAD and decrypt
        aad_dict = {
            "version": payload.get("version", 1),
            "channel_id": channel_id,
            "sender_id": sender_id,
            "sequence": seq,
            "timestamp": timestamp,
        }
        aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")

        try:
            plaintext = crypto.decrypt_message(ciphertext, iv, group_key, aad)
        except Exception:
            print(f"[TAMPER] Decryption failed for message from {sender_id} "
                  f"seq={seq} -- message modified or wrong key")
            continue

        # 5. Unpad if needed
        if payload.get("padded", False):
            try:
                plaintext = pad_module.unpad_message(plaintext)
            except ValueError as e:
                print(f"[ERROR] Padding invalid for message from {sender_id}: {e}")
                continue

        # 6. Accept: update sequence counter, print plaintext
        state.update_seq(sender_id, seq)
        accepted_sequences.append(seq)
        decoded = plaintext.decode("utf-8")
        print(f"[MSG] {sender_id} (seq={seq}): {decoded}")

    if not messages:
        print("[INFO] No messages found.")

    # Gap detection
    if check_gaps and accepted_sequences:
        for sender_id_check in set(
            m.get("sender_id", "") for m in messages
        ):
            sender_seqs = sorted(
                m.get("sequence", 0)
                for m in messages
                if m.get("sender_id") == sender_id_check
            )
            if len(sender_seqs) >= 2:
                expected = set(range(sender_seqs[0], sender_seqs[-1] + 1))
                received = set(sender_seqs)
                missing = expected - received
                if missing:
                    print(
                        f"[WARNING] Missing sequence numbers from "
                        f"{sender_id_check}: {sorted(missing)}"
                    )
                    print(
                        f"  Possible message deletion by Slack admin "
                        f"or network loss."
                    )


# ---------------------------------------------------------------------------
# Subcommand: verify (signature check only, no decryption)
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> None:
    """Fetch messages and verify signatures only (no decryption)."""
    channel = args.channel
    receiver = args.receiver

    messages = slack_interface.fetch_messages(channel, args.limit)
    messages.sort(key=lambda m: m.get("sequence", 0))

    for payload in messages:
        sender_id = payload.get("sender_id", "unknown")
        seq = payload.get("sequence", 0)

        try:
            iv = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            signature = base64.b64decode(payload["signature"])
        except (KeyError, Exception) as e:
            print(f"[ERROR] Malformed message from {sender_id}: {e}")
            continue

        timestamp = payload.get("timestamp", "")
        channel_id = payload.get("channel_id", channel)

        signed_blob = crypto.build_signed_blob(
            ciphertext, iv, sender_id, seq, timestamp, channel_id
        )
        try:
            sender_ed_pub = crypto.load_ed25519_public(
                _key_path(sender_id, "ed25519", "public")
            )
            crypto.verify_signature(sender_ed_pub, signed_blob, signature)
            print(f"[VALID] {sender_id} seq={seq} -- signature OK")
        except FileNotFoundError:
            print(f"[SPOOF] No public key found for sender '{sender_id}'")
        except Exception:
            print(f"[SPOOF] Signature INVALID for {sender_id} seq={seq}")


# ---------------------------------------------------------------------------
# Subcommand: addmember
# ---------------------------------------------------------------------------

def cmd_addmember(args: argparse.Namespace) -> None:
    """Wrap the existing group key for a new member."""
    channel = args.channel
    admin = args.admin
    member = args.member

    _ensure_dirs()

    # Load admin's group key
    try:
        admin_entry = state.get_group_key(channel, admin)
    except KeyError:
        print(f"[ERROR] Admin '{admin}' not found on channel '{channel}'")
        sys.exit(1)

    group_key = bytes.fromhex(admin_entry["plaintext_hex"])

    # Load keys
    admin_x_priv = crypto.load_x25519_private(
        _key_path(admin, "x25519", "private")
    )
    member_x_pub = crypto.load_x25519_public(
        _key_path(member, "x25519", "public")
    )

    # Wrap and store
    wrapped = crypto.wrap_group_key(group_key, member_x_pub, admin_x_priv, channel)
    state.add_member_key(channel, member, wrapped, admin_entry["plaintext_hex"])

    print(f"[OK] Added '{member}' to channel '{channel}'")


# ---------------------------------------------------------------------------
# Subcommand: revoke
# ---------------------------------------------------------------------------

def cmd_revoke(args: argparse.Namespace) -> None:
    """Revoke a member and rotate the group key."""
    channel = args.channel
    admin = args.admin
    member = args.member

    _ensure_dirs()

    # Get current members before revocation
    try:
        current_members = state.get_channel_members(channel)
    except KeyError:
        print(f"[ERROR] Channel '{channel}' not found")
        sys.exit(1)

    if member not in current_members:
        print(f"[ERROR] '{member}' is not a member of '{channel}'")
        sys.exit(1)

    remaining = [m for m in current_members if m != member]

    # Generate new group key
    new_group_key = os.urandom(32)
    new_group_key_hex = new_group_key.hex()

    # Load admin's private key
    admin_x_priv = crypto.load_x25519_private(
        _key_path(admin, "x25519", "private")
    )

    # Wrap new key for remaining members only
    new_key_id = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    new_wrapped = {}
    for m in remaining:
        m_x_pub = crypto.load_x25519_public(_key_path(m, "x25519", "public"))
        new_wrapped[m] = crypto.wrap_group_key(
            new_group_key, m_x_pub, admin_x_priv, channel
        )

    # Rotate key in state
    state.rotate_key(channel, admin, new_key_id, new_wrapped, new_group_key_hex)

    # Move revoked member's keys to revoked/
    for key_type in ("x25519", "ed25519"):
        for access in ("private", "public"):
            src = _key_path(member, key_type, access)
            if os.path.exists(src):
                dst = os.path.join(REVOKED_DIR, os.path.basename(src))
                shutil.move(src, dst)

    print(f"[OK] Revoked '{member}' from channel '{channel}'")
    print(f"  New key ID: {new_key_id}")
    print(f"  Remaining members: {', '.join(remaining)}")


# ---------------------------------------------------------------------------
# Subcommand: rotate
# ---------------------------------------------------------------------------

def cmd_rotate(args: argparse.Namespace) -> None:
    """Generate a new group key and re-wrap for all current members."""
    channel = args.channel
    admin = args.admin

    try:
        current_members = state.get_channel_members(channel)
    except KeyError:
        print(f"[ERROR] Channel '{channel}' not found")
        sys.exit(1)

    new_group_key = os.urandom(32)
    new_group_key_hex = new_group_key.hex()

    admin_x_priv = crypto.load_x25519_private(
        _key_path(admin, "x25519", "private")
    )

    new_key_id = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    new_wrapped = {}
    for m in current_members:
        m_x_pub = crypto.load_x25519_public(_key_path(m, "x25519", "public"))
        new_wrapped[m] = crypto.wrap_group_key(
            new_group_key, m_x_pub, admin_x_priv, channel
        )

    state.rotate_key(channel, admin, new_key_id, new_wrapped, new_group_key_hex)

    print(f"[OK] Key rotated for channel '{channel}'")
    print(f"  New key ID: {new_key_id}")
    print(f"  Members: {', '.join(current_members)}")


# ---------------------------------------------------------------------------
# Subcommand: replay (for demo purposes)
# ---------------------------------------------------------------------------

def cmd_replay(args: argparse.Namespace) -> None:
    """Re-post an old message to simulate a replay attack (demo only)."""
    channel = args.channel
    target_seq = args.seq

    messages = slack_interface.fetch_messages(channel, limit=50)
    target = None
    for m in messages:
        if m.get("sequence") == target_seq:
            target = m
            break

    if not target:
        print(f"[ERROR] No message with seq={target_seq} found in #{channel}")
        sys.exit(1)

    # Re-post the exact same message (replay)
    slack_interface.post_message(channel, target)
    print(f"[REPLAY-ATTACK] Re-posted message seq={target_seq} to #{channel}")


# ---------------------------------------------------------------------------
# Argument Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser with all subcommands."""
    parser = argparse.ArgumentParser(
        description="E2E Encrypted Slack Messaging -- NYU CS6903 Project 2.2"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate keypairs")
    p_keygen.add_argument("--name", required=True, help="User name")

    # fingerprint
    p_fp = subparsers.add_parser("fingerprint", help="Show key fingerprints")
    p_fp.add_argument("--name", required=True, help="User name")

    # init-channel
    p_init = subparsers.add_parser("init-channel", help="Initialize a channel")
    p_init.add_argument("--channel", required=True, help="Channel name")
    p_init.add_argument("--admin", required=True, help="Admin user name")
    p_init.add_argument("--members", required=True,
                        help="Comma-separated member names")

    # post
    p_post = subparsers.add_parser("post", help="Encrypt and post a message")
    p_post.add_argument("--channel", required=True, help="Channel name")
    p_post.add_argument("--sender", required=True, help="Sender user name")
    p_post.add_argument("--message", required=True, help="Plaintext message")
    p_post.add_argument("--pad", action="store_true",
                        help="Pad message to fixed block size")
    p_post.add_argument("--spoof-sender-id", default=None,
                        help="Claim to be this sender (spoofing demo)")

    # fetch
    p_fetch = subparsers.add_parser("fetch", help="Fetch and decrypt messages")
    p_fetch.add_argument("--channel", required=True, help="Channel name")
    p_fetch.add_argument("--receiver", required=True, help="Receiver user name")
    p_fetch.add_argument("--limit", type=int, default=20,
                         help="Max messages to fetch")
    p_fetch.add_argument("--check-gaps", action="store_true",
                         help="Detect missing sequence numbers")

    # verify
    p_verify = subparsers.add_parser("verify",
                                     help="Verify signatures only (no decrypt)")
    p_verify.add_argument("--channel", required=True, help="Channel name")
    p_verify.add_argument("--receiver", required=True, help="Receiver user name")
    p_verify.add_argument("--limit", type=int, default=20,
                          help="Max messages to fetch")

    # addmember
    p_add = subparsers.add_parser("addmember", help="Add a member to a channel")
    p_add.add_argument("--channel", required=True, help="Channel name")
    p_add.add_argument("--admin", required=True, help="Admin user name")
    p_add.add_argument("--member", required=True, help="New member name")

    # revoke
    p_rev = subparsers.add_parser("revoke",
                                  help="Revoke a member and rotate key")
    p_rev.add_argument("--channel", required=True, help="Channel name")
    p_rev.add_argument("--admin", required=True, help="Admin user name")
    p_rev.add_argument("--member", required=True, help="Member to revoke")

    # rotate
    p_rot = subparsers.add_parser("rotate", help="Rotate the group key")
    p_rot.add_argument("--channel", required=True, help="Channel name")
    p_rot.add_argument("--admin", required=True, help="Admin user name")

    # replay (demo)
    p_replay = subparsers.add_parser("replay",
                                     help="Re-post an old message (demo attack)")
    p_replay.add_argument("--channel", required=True, help="Channel name")
    p_replay.add_argument("--seq", type=int, required=True,
                          help="Sequence number of message to replay")

    return parser


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "keygen": cmd_keygen,
        "fingerprint": cmd_fingerprint,
        "init-channel": cmd_init_channel,
        "post": cmd_post,
        "fetch": cmd_fetch,
        "verify": cmd_verify,
        "addmember": cmd_addmember,
        "revoke": cmd_revoke,
        "rotate": cmd_rotate,
        "replay": cmd_replay,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

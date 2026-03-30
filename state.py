"""
state.py -- Replay prevention and group key state management.
NYU CS6903/4783 Project 2.2

Manages two JSON state files:
    - state/sequence_state.json  (per-sender monotonic sequence counters)
    - state/group_keys.json      (per-channel wrapped group keys)

Sequence counters are updated ONLY after full verification (signature + GCM
tag both pass). Never update state on a failed message.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional


STATE_DIR = "state"
SEQ_FILE = os.path.join(STATE_DIR, "sequence_state.json")
KEY_FILE = os.path.join(STATE_DIR, "group_keys.json")


def _ensure_state_dir() -> None:
    """Create the state directory if it does not exist."""
    os.makedirs(STATE_DIR, exist_ok=True)


def _load_json(path: str) -> dict:
    """Load a JSON file, returning an empty dict if it does not exist."""
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _save_json(path: str, data: dict) -> None:
    """Atomically write a dict to a JSON file."""
    _ensure_state_dir()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Sequence State (replay prevention)
# ---------------------------------------------------------------------------

def get_next_send_seq(sender_id: str) -> int:
    """Return the next sequence number for an outbound message.

    Uses a separate namespace ("send:...") from the receive-side counter
    so that sender and receiver can coexist on the same machine (as in
    the single-machine demo) without the sender's update causing the
    receiver's replay check to reject the message.

    Args:
        sender_id: Identifier of the sender.

    Returns:
        Next sequence number (>= 1).
    """
    state = _load_json(SEQ_FILE)
    return state.get(f"send:{sender_id}", 0) + 1


def update_send_seq(sender_id: str, seq: int) -> None:
    """Record the latest outbound sequence number after posting.

    Args:
        sender_id: Identifier of the sender.
        seq: The sequence number just used.
    """
    state = _load_json(SEQ_FILE)
    state[f"send:{sender_id}"] = seq
    _save_json(SEQ_FILE, state)


def get_last_seq(sender_id: str) -> int:
    """Return the highest accepted receive-side sequence for a sender.

    Args:
        sender_id: Identifier of the sender.

    Returns:
        Last accepted sequence number, or 0 if never seen.
    """
    state = _load_json(SEQ_FILE)
    return state.get(f"recv:{sender_id}", 0)


def update_seq(sender_id: str, seq: int) -> None:
    """Record a new highest accepted receive-side sequence number.

    ONLY call this after FULL verification (signature + GCM tag both pass).
    Never update state on a failed message.

    Args:
        sender_id: Identifier of the sender.
        seq: The sequence number that was just verified.
    """
    state = _load_json(SEQ_FILE)
    state[f"recv:{sender_id}"] = seq
    _save_json(SEQ_FILE, state)


def is_replay(sender_id: str, seq: int) -> bool:
    """Check whether a sequence number is a replay (receive-side).

    Args:
        sender_id: Identifier of the sender.
        seq: Sequence number from the incoming message.

    Returns:
        True if seq <= last accepted receive-side seq for this sender.
    """
    return seq <= get_last_seq(sender_id)


# ---------------------------------------------------------------------------
# Group Key State
# ---------------------------------------------------------------------------

def init_channel(
    channel_id: str,
    admin_id: str,
    key_id: str,
    wrapped_keys: dict,
    plaintext_hex: Optional[str] = None,
) -> None:
    """Create a channel entry in group_keys.json.

    Args:
        channel_id: Channel identifier.
        admin_id: User who created the channel.
        key_id: Unique identifier for this key generation event.
        wrapped_keys: Mapping of member_id -> {ciphertext, iv} dicts.
        plaintext_hex: Hex-encoded plaintext group key (stored locally
                       for convenience during development/demo).
    """
    state = _load_json(KEY_FILE)
    members = {}
    for member_id, blob in wrapped_keys.items():
        entry = {"ciphertext": blob["ciphertext"], "iv": blob["iv"]}
        if plaintext_hex:
            entry["plaintext_hex"] = plaintext_hex
        members[member_id] = entry

    state[channel_id] = {
        "current_key_id": key_id,
        "keys": {
            key_id: {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_by": admin_id,
                "members": members,
            }
        },
    }
    _save_json(KEY_FILE, state)


def get_group_key(channel_id: str, member_id: str) -> dict:
    """Retrieve the wrapped key blob for a member on a channel.

    Args:
        channel_id: Channel identifier.
        member_id: The member whose wrapped key to retrieve.

    Returns:
        Dict with 'ciphertext', 'iv', and optionally 'plaintext_hex'.

    Raises:
        KeyError: If the channel or member is not found.
    """
    state = _load_json(KEY_FILE)
    if channel_id not in state:
        raise KeyError(f"Channel '{channel_id}' not found in group key state")
    current_key_id = state[channel_id]["current_key_id"]
    key_data = state[channel_id]["keys"][current_key_id]
    if member_id not in key_data["members"]:
        raise KeyError(
            f"Member '{member_id}' not found in channel '{channel_id}' "
            f"(key_id={current_key_id})"
        )
    return key_data["members"][member_id]


def get_channel_members(channel_id: str) -> list:
    """Return a list of member IDs in the current key for a channel.

    Args:
        channel_id: Channel identifier.

    Returns:
        List of member ID strings.

    Raises:
        KeyError: If the channel is not found.
    """
    state = _load_json(KEY_FILE)
    if channel_id not in state:
        raise KeyError(f"Channel '{channel_id}' not found")
    current_key_id = state[channel_id]["current_key_id"]
    return list(state[channel_id]["keys"][current_key_id]["members"].keys())


def add_member_key(
    channel_id: str,
    member_id: str,
    wrapped_key: dict,
    plaintext_hex: Optional[str] = None,
) -> None:
    """Add a new member's wrapped key to a channel.

    Args:
        channel_id: Channel identifier.
        member_id: New member's identifier.
        wrapped_key: Dict with 'ciphertext' and 'iv'.
        plaintext_hex: Optional hex-encoded plaintext group key.

    Raises:
        KeyError: If the channel is not found.
    """
    state = _load_json(KEY_FILE)
    if channel_id not in state:
        raise KeyError(f"Channel '{channel_id}' not found")
    current_key_id = state[channel_id]["current_key_id"]
    entry = {"ciphertext": wrapped_key["ciphertext"], "iv": wrapped_key["iv"]}
    if plaintext_hex:
        entry["plaintext_hex"] = plaintext_hex
    state[channel_id]["keys"][current_key_id]["members"][member_id] = entry
    _save_json(KEY_FILE, state)


def rotate_key(
    channel_id: str,
    admin_id: str,
    new_key_id: str,
    new_wrapped_keys: dict,
    plaintext_hex: Optional[str] = None,
) -> None:
    """Replace all wrapped keys with a new generation.

    Old keys remain in the JSON for historical reference but the
    current_key_id pointer moves to the new key.

    Args:
        channel_id: Channel identifier.
        admin_id: Admin performing the rotation.
        new_key_id: Unique identifier for the new key.
        new_wrapped_keys: Mapping of member_id -> {ciphertext, iv}.
        plaintext_hex: Optional hex-encoded new plaintext group key.

    Raises:
        KeyError: If the channel is not found.
    """
    state = _load_json(KEY_FILE)
    if channel_id not in state:
        raise KeyError(f"Channel '{channel_id}' not found")

    members = {}
    for member_id, blob in new_wrapped_keys.items():
        entry = {"ciphertext": blob["ciphertext"], "iv": blob["iv"]}
        if plaintext_hex:
            entry["plaintext_hex"] = plaintext_hex
        members[member_id] = entry

    state[channel_id]["keys"][new_key_id] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": admin_id,
        "members": members,
    }
    state[channel_id]["current_key_id"] = new_key_id
    _save_json(KEY_FILE, state)


def revoke_member(channel_id: str, member_id: str) -> None:
    """Remove a member from the current key's member list.

    This should be followed by a key rotation that excludes the
    revoked member.

    Args:
        channel_id: Channel identifier.
        member_id: Member to revoke.

    Raises:
        KeyError: If the channel or member is not found.
    """
    state = _load_json(KEY_FILE)
    if channel_id not in state:
        raise KeyError(f"Channel '{channel_id}' not found")
    current_key_id = state[channel_id]["current_key_id"]
    members = state[channel_id]["keys"][current_key_id]["members"]
    if member_id not in members:
        raise KeyError(f"Member '{member_id}' not in channel '{channel_id}'")
    del members[member_id]
    _save_json(KEY_FILE, state)

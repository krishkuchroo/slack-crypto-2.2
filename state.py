import json
import os
from datetime import datetime, timezone
from typing import Optional


STATE_DIR = "state"
SEQ_FILE = os.path.join(STATE_DIR, "sequence_state.json")
KEY_FILE = os.path.join(STATE_DIR, "group_keys.json")


def _ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _save_json(path: str, data: dict) -> None:
    _ensure_state_dir()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_next_send_seq(sender_id: str) -> int:
    state = _load_json(SEQ_FILE)
    return state.get(f"send:{sender_id}", 0) + 1


def update_send_seq(sender_id: str, seq: int) -> None:
    state = _load_json(SEQ_FILE)
    state[f"send:{sender_id}"] = seq
    _save_json(SEQ_FILE, state)


def get_last_seq(sender_id: str) -> int:
    state = _load_json(SEQ_FILE)
    return state.get(f"recv:{sender_id}", 0)


def update_seq(sender_id: str, seq: int) -> None:
    state = _load_json(SEQ_FILE)
    state[f"recv:{sender_id}"] = seq
    _save_json(SEQ_FILE, state)


def is_replay(sender_id: str, seq: int) -> bool:
    return seq <= get_last_seq(sender_id)


def init_channel(
    channel_id: str,
    admin_id: str,
    key_id: str,
    wrapped_keys: dict,
    plaintext_hex: Optional[str] = None,
) -> None:
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
    state = _load_json(KEY_FILE)
    if channel_id not in state:
        raise KeyError(f"Channel '{channel_id}' not found")
    current_key_id = state[channel_id]["current_key_id"]
    members = state[channel_id]["keys"][current_key_id]["members"]
    if member_id not in members:
        raise KeyError(f"Member '{member_id}' not in channel '{channel_id}'")
    del members[member_id]
    _save_json(KEY_FILE, state)

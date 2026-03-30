"""
test_integration.py -- Integration tests with mocked Slack interface.
NYU CS6903/4783 Project 2.2

Tests the full send/receive pipeline without a real Slack connection.
"""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto
import state
import padding as pad_module


class MockSlackChannel:
    """In-memory mock of a Slack channel for testing."""

    def __init__(self):
        self.messages = []

    def post(self, payload: dict):
        self.messages.append(payload)

    def fetch(self, limit=20):
        return list(reversed(self.messages[-limit:]))


class IntegrationTestBase(unittest.TestCase):
    """Base class that sets up keys, state dirs, and mock Slack."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.keys_dir = os.path.join(self.tmpdir, "keys")
        os.makedirs(self.keys_dir)

        # Redirect state module to temp dir
        self.orig_state_dir = state.STATE_DIR
        state.STATE_DIR = os.path.join(self.tmpdir, "state")
        state.SEQ_FILE = os.path.join(state.STATE_DIR, "sequence_state.json")
        state.KEY_FILE = os.path.join(state.STATE_DIR, "group_keys.json")
        os.makedirs(state.STATE_DIR, exist_ok=True)

        self.channel = MockSlackChannel()
        self.channel_id = "test-channel"

        # Generate keys for alice and bob
        self.alice_x_priv, self.alice_x_pub = crypto.generate_x25519_keypair()
        self.alice_ed_priv, self.alice_ed_pub = crypto.generate_ed25519_keypair()
        self.bob_x_priv, self.bob_x_pub = crypto.generate_x25519_keypair()
        self.bob_ed_priv, self.bob_ed_pub = crypto.generate_ed25519_keypair()

        # Save keys
        for name, priv, pub, ktype in [
            ("alice", self.alice_x_priv, self.alice_x_pub, "x25519"),
            ("alice", self.alice_ed_priv, self.alice_ed_pub, "ed25519"),
            ("bob", self.bob_x_priv, self.bob_x_pub, "x25519"),
            ("bob", self.bob_ed_priv, self.bob_ed_pub, "ed25519"),
        ]:
            crypto.save_private_key(
                priv, os.path.join(self.keys_dir, f"{name}_{ktype}_private.pem")
            )
            crypto.save_public_key(
                pub, os.path.join(self.keys_dir, f"{name}_{ktype}_public.pem")
            )

        # Generate and distribute group key
        self.group_key = os.urandom(32)
        alice_wrapped = crypto.wrap_group_key(
            self.group_key, self.alice_x_pub, self.alice_x_priv, self.channel_id
        )
        bob_wrapped = crypto.wrap_group_key(
            self.group_key, self.bob_x_pub, self.alice_x_priv, self.channel_id
        )
        state.init_channel(
            self.channel_id, "alice", "key-001",
            {"alice": alice_wrapped, "bob": bob_wrapped},
            self.group_key.hex(),
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        state.STATE_DIR = self.orig_state_dir
        state.SEQ_FILE = os.path.join(self.orig_state_dir, "sequence_state.json")
        state.KEY_FILE = os.path.join(self.orig_state_dir, "group_keys.json")

    def _send_message(self, sender_id, sender_ed_priv, message_text, seq=None,
                      use_padding=False, spoof_sender=None):
        """Simulate the full send pipeline."""
        claimed_sender = spoof_sender if spoof_sender else sender_id
        plaintext = message_text.encode("utf-8")
        if use_padding:
            plaintext = pad_module.pad_message(plaintext)

        if seq is None:
            seq = state.get_next_send_seq(claimed_sender)
        timestamp = datetime.now(timezone.utc).isoformat()

        aad_dict = {
            "version": 1,
            "channel_id": self.channel_id,
            "sender_id": claimed_sender,
            "sequence": seq,
            "timestamp": timestamp,
        }
        aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")

        ciphertext, iv = crypto.encrypt_message(plaintext, self.group_key, aad)
        signed_blob = crypto.build_signed_blob(
            ciphertext, iv, claimed_sender, seq, timestamp, self.channel_id
        )
        signature = crypto.sign_message(sender_ed_priv, signed_blob)

        payload = {
            "version": 1,
            "channel_id": self.channel_id,
            "sender_id": claimed_sender,
            "sequence": seq,
            "timestamp": timestamp,
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
            "padded": use_padding,
        }
        self.channel.post(payload)
        state.update_send_seq(claimed_sender, seq)
        return payload

    def _receive_messages(self, receiver_id, receiver_ed_pub_loader):
        """Simulate the full receive pipeline. Returns list of results."""
        messages = self.channel.fetch()
        messages.sort(key=lambda m: m.get("sequence", 0))

        results = []
        for payload in messages:
            sender_id = payload.get("sender_id", "unknown")
            seq = payload.get("sequence", 0)

            if state.is_replay(sender_id, seq):
                results.append(("REPLAY", sender_id, seq, None))
                continue

            iv = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            signature = base64.b64decode(payload["signature"])
            timestamp = payload.get("timestamp", "")
            channel_id = payload.get("channel_id", self.channel_id)

            signed_blob = crypto.build_signed_blob(
                ciphertext, iv, sender_id, seq, timestamp, channel_id
            )

            try:
                sender_pub = receiver_ed_pub_loader(sender_id)
                crypto.verify_signature(sender_pub, signed_blob, signature)
            except Exception:
                results.append(("SPOOF", sender_id, seq, None))
                continue

            aad_dict = {
                "version": payload.get("version", 1),
                "channel_id": channel_id,
                "sender_id": sender_id,
                "sequence": seq,
                "timestamp": timestamp,
            }
            aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")

            try:
                key_entry = state.get_group_key(self.channel_id, receiver_id)
                group_key = bytes.fromhex(key_entry["plaintext_hex"])
                plaintext = crypto.decrypt_message(ciphertext, iv, group_key, aad)
            except Exception:
                results.append(("TAMPER", sender_id, seq, None))
                continue

            if payload.get("padded", False):
                plaintext = pad_module.unpad_message(plaintext)

            state.update_seq(sender_id, seq)
            results.append(("OK", sender_id, seq, plaintext.decode("utf-8")))

        return results


class TestNormalFlow(IntegrationTestBase):
    """Test normal send/receive cycle."""

    def test_roundtrip(self):
        self._send_message("alice", self.alice_ed_priv, "Hello Bob!")

        def pub_loader(sid):
            if sid == "alice":
                return self.alice_ed_pub
            return self.bob_ed_pub

        results = self._receive_messages("bob", pub_loader)
        self.assertEqual(len(results), 1)
        status, sender, seq, text = results[0]
        self.assertEqual(status, "OK")
        self.assertEqual(sender, "alice")
        self.assertEqual(text, "Hello Bob!")

    def test_multiple_messages(self):
        self._send_message("alice", self.alice_ed_priv, "Message 1")
        self._send_message("alice", self.alice_ed_priv, "Message 2")

        def pub_loader(sid):
            return self.alice_ed_pub if sid == "alice" else self.bob_ed_pub

        results = self._receive_messages("bob", pub_loader)
        ok_results = [r for r in results if r[0] == "OK"]
        self.assertEqual(len(ok_results), 2)
        self.assertEqual(ok_results[0][3], "Message 1")
        self.assertEqual(ok_results[1][3], "Message 2")


class TestTamperDetection(IntegrationTestBase):
    """Test that ciphertext modification is detected."""

    def test_tampered_ciphertext_rejected(self):
        self._send_message("alice", self.alice_ed_priv, "Secret")

        # Tamper with ciphertext in the channel
        msg = self.channel.messages[0]
        ct_bytes = bytearray(base64.b64decode(msg["ciphertext"]))
        ct_bytes[0] ^= 0xFF
        msg["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")

        def pub_loader(sid):
            return self.alice_ed_pub

        results = self._receive_messages("bob", pub_loader)
        # Should be SPOOF or TAMPER (since signature now fails on modified ct)
        self.assertIn(results[0][0], ("SPOOF", "TAMPER"))


class TestSpoofDetection(IntegrationTestBase):
    """Test that spoofed sender is detected."""

    def test_spoofed_sender_rejected(self):
        # Mallory generates her own keys
        mallory_ed_priv, mallory_ed_pub = crypto.generate_ed25519_keypair()

        # Mallory sends claiming to be alice (signs with her own key)
        self._send_message(
            "mallory", mallory_ed_priv, "I am totally alice",
            spoof_sender="alice", seq=99
        )

        def pub_loader(sid):
            if sid == "alice":
                return self.alice_ed_pub  # Bob loads alice's real key
            return self.bob_ed_pub

        results = self._receive_messages("bob", pub_loader)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], "SPOOF")


class TestReplayDetection(IntegrationTestBase):
    """Test that replay attacks are detected."""

    def test_replay_rejected(self):
        self._send_message("alice", self.alice_ed_priv, "Original")

        def pub_loader(sid):
            return self.alice_ed_pub

        # First receive
        results1 = self._receive_messages("bob", pub_loader)
        self.assertEqual(results1[0][0], "OK")

        # Re-post the same message (replay)
        replayed = self.channel.messages[0].copy()
        self.channel.messages.append(replayed)

        # Second receive
        results2 = self._receive_messages("bob", pub_loader)
        replays = [r for r in results2 if r[0] == "REPLAY"]
        self.assertGreater(len(replays), 0)


class TestKeyRotation(IntegrationTestBase):
    """Test that key rotation excludes revoked members."""

    def test_revoked_member_cannot_decrypt(self):
        # Generate carol's keys
        carol_x_priv, carol_x_pub = crypto.generate_x25519_keypair()
        carol_ed_priv, carol_ed_pub = crypto.generate_ed25519_keypair()

        # Add carol
        carol_wrapped = crypto.wrap_group_key(
            self.group_key, carol_x_pub, self.alice_x_priv, self.channel_id
        )
        state.add_member_key(
            self.channel_id, "carol", carol_wrapped, self.group_key.hex()
        )

        # Verify carol can access key
        entry = state.get_group_key(self.channel_id, "carol")
        self.assertIsNotNone(entry)

        # Rotate key excluding carol
        new_group_key = os.urandom(32)
        alice_new = crypto.wrap_group_key(
            new_group_key, self.alice_x_pub, self.alice_x_priv, self.channel_id
        )
        bob_new = crypto.wrap_group_key(
            new_group_key, self.bob_x_pub, self.alice_x_priv, self.channel_id
        )
        state.rotate_key(
            self.channel_id, "alice", "key-002",
            {"alice": alice_new, "bob": bob_new},
            new_group_key.hex(),
        )

        # Carol should not be in the new key
        with self.assertRaises(KeyError):
            state.get_group_key(self.channel_id, "carol")


class TestPaddingRoundtrip(IntegrationTestBase):
    """Test message padding roundtrip."""

    def test_padded_message_roundtrip(self):
        self._send_message(
            "alice", self.alice_ed_priv, "Short msg", use_padding=True
        )

        def pub_loader(sid):
            return self.alice_ed_pub

        results = self._receive_messages("bob", pub_loader)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], "OK")
        self.assertEqual(results[0][3], "Short msg")


class TestPaddingModule(unittest.TestCase):
    """Test padding.py directly."""

    def test_pad_unpad_roundtrip(self):
        msg = b"hello"
        padded = pad_module.pad_message(msg, 32)
        self.assertEqual(len(padded) % 32, 0)
        unpadded = pad_module.unpad_message(padded)
        self.assertEqual(unpadded, msg)

    def test_default_block_size_512(self):
        msg = b"short"
        padded = pad_module.pad_message(msg)
        self.assertEqual(len(padded) % 512, 0)
        unpadded = pad_module.unpad_message(padded)
        self.assertEqual(unpadded, msg)

    def test_exact_alignment_gets_extra_block(self):
        # 28 bytes of plaintext + 4 bytes header = 32, should get padded to 64
        msg = b"A" * 28
        padded = pad_module.pad_message(msg, 32)
        self.assertEqual(len(padded), 64)
        self.assertEqual(pad_module.unpad_message(padded), msg)

    def test_unpad_too_short_raises(self):
        with self.assertRaises(ValueError):
            pad_module.unpad_message(b"\x00\x01")

    def test_invalid_length_prefix_raises(self):
        import struct
        # Claim 1000 bytes but provide only 10
        bad = struct.pack(">I", 1000) + b"\x00" * 10
        with self.assertRaises(ValueError):
            pad_module.unpad_message(bad)


if __name__ == "__main__":
    unittest.main()

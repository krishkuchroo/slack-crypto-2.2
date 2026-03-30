"""
test_state.py -- Unit tests for state.py
NYU CS6903/4783 Project 2.2
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import state


class TestSequenceState(unittest.TestCase):
    """Test replay prevention via sequence counters."""

    def setUp(self):
        self.orig_dir = state.STATE_DIR
        self.tmpdir = tempfile.mkdtemp()
        state.STATE_DIR = self.tmpdir
        state.SEQ_FILE = os.path.join(self.tmpdir, "sequence_state.json")
        state.KEY_FILE = os.path.join(self.tmpdir, "group_keys.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        state.STATE_DIR = self.orig_dir
        state.SEQ_FILE = os.path.join(self.orig_dir, "sequence_state.json")
        state.KEY_FILE = os.path.join(self.orig_dir, "group_keys.json")

    def test_get_last_seq_default(self):
        self.assertEqual(state.get_last_seq("alice"), 0)

    def test_update_and_get_seq(self):
        state.update_seq("alice", 5)
        self.assertEqual(state.get_last_seq("alice"), 5)

    def test_get_next_seq(self):
        self.assertEqual(state.get_next_send_seq("alice"), 1)
        state.update_send_seq("alice", 1)
        self.assertEqual(state.get_next_send_seq("alice"), 2)

    def test_is_replay_true(self):
        state.update_seq("alice", 3)
        self.assertTrue(state.is_replay("alice", 1))
        self.assertTrue(state.is_replay("alice", 2))
        self.assertTrue(state.is_replay("alice", 3))

    def test_is_replay_false(self):
        state.update_seq("alice", 3)
        self.assertFalse(state.is_replay("alice", 4))
        self.assertFalse(state.is_replay("alice", 100))

    def test_is_replay_new_sender(self):
        self.assertFalse(state.is_replay("newuser", 1))

    def test_seq_persists_across_calls(self):
        state.update_seq("bob", 10)
        # Simulate a fresh load by reading the file directly
        with open(state.SEQ_FILE, "r") as f:
            data = json.load(f)
        self.assertEqual(data["recv:bob"], 10)

    def test_multiple_senders_independent(self):
        state.update_seq("alice", 5)
        state.update_seq("bob", 10)
        self.assertEqual(state.get_last_seq("alice"), 5)
        self.assertEqual(state.get_last_seq("bob"), 10)
        self.assertTrue(state.is_replay("alice", 5))
        self.assertFalse(state.is_replay("alice", 6))

    def test_send_and_recv_independent(self):
        """Send-side and receive-side seq counters must not collide."""
        state.update_send_seq("alice", 5)
        # Receive-side should still be 0
        self.assertEqual(state.get_last_seq("alice"), 0)
        self.assertFalse(state.is_replay("alice", 1))
        # Send-side should be 5
        self.assertEqual(state.get_next_send_seq("alice"), 6)


class TestGroupKeyState(unittest.TestCase):
    """Test group key state management."""

    def setUp(self):
        self.orig_dir = state.STATE_DIR
        self.tmpdir = tempfile.mkdtemp()
        state.STATE_DIR = self.tmpdir
        state.SEQ_FILE = os.path.join(self.tmpdir, "sequence_state.json")
        state.KEY_FILE = os.path.join(self.tmpdir, "group_keys.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        state.STATE_DIR = self.orig_dir
        state.SEQ_FILE = os.path.join(self.orig_dir, "sequence_state.json")
        state.KEY_FILE = os.path.join(self.orig_dir, "group_keys.json")

    def test_init_channel(self):
        wrapped = {
            "alice": {"ciphertext": "aabb", "iv": "ccdd"},
            "bob": {"ciphertext": "eeff", "iv": "1122"},
        }
        state.init_channel("ch1", "alice", "key-001", wrapped, "deadbeef" * 8)

        entry = state.get_group_key("ch1", "alice")
        self.assertEqual(entry["ciphertext"], "aabb")
        self.assertEqual(entry["iv"], "ccdd")
        self.assertEqual(entry["plaintext_hex"], "deadbeef" * 8)

    def test_get_group_key_missing_channel(self):
        with self.assertRaises(KeyError):
            state.get_group_key("nonexistent", "alice")

    def test_get_group_key_missing_member(self):
        wrapped = {"alice": {"ciphertext": "aa", "iv": "bb"}}
        state.init_channel("ch1", "alice", "key-001", wrapped)
        with self.assertRaises(KeyError):
            state.get_group_key("ch1", "bob")

    def test_get_channel_members(self):
        wrapped = {
            "alice": {"ciphertext": "aa", "iv": "bb"},
            "bob": {"ciphertext": "cc", "iv": "dd"},
        }
        state.init_channel("ch1", "alice", "key-001", wrapped)
        members = state.get_channel_members("ch1")
        self.assertEqual(sorted(members), ["alice", "bob"])

    def test_add_member_key(self):
        wrapped = {"alice": {"ciphertext": "aa", "iv": "bb"}}
        state.init_channel("ch1", "alice", "key-001", wrapped, "aabb" * 16)

        state.add_member_key("ch1", "bob", {"ciphertext": "cc", "iv": "dd"}, "aabb" * 16)

        entry = state.get_group_key("ch1", "bob")
        self.assertEqual(entry["ciphertext"], "cc")

    def test_rotate_key(self):
        wrapped = {
            "alice": {"ciphertext": "aa", "iv": "bb"},
            "bob": {"ciphertext": "cc", "iv": "dd"},
        }
        state.init_channel("ch1", "alice", "key-001", wrapped, "old_hex")

        new_wrapped = {
            "alice": {"ciphertext": "ee", "iv": "ff"},
            "bob": {"ciphertext": "11", "iv": "22"},
        }
        state.rotate_key("ch1", "alice", "key-002", new_wrapped, "new_hex")

        entry = state.get_group_key("ch1", "alice")
        self.assertEqual(entry["ciphertext"], "ee")
        self.assertEqual(entry["plaintext_hex"], "new_hex")

        # Verify current_key_id updated
        data = state._load_json(state.KEY_FILE)
        self.assertEqual(data["ch1"]["current_key_id"], "key-002")
        # Old key still in history
        self.assertIn("key-001", data["ch1"]["keys"])

    def test_revoke_member(self):
        wrapped = {
            "alice": {"ciphertext": "aa", "iv": "bb"},
            "bob": {"ciphertext": "cc", "iv": "dd"},
            "carol": {"ciphertext": "ee", "iv": "ff"},
        }
        state.init_channel("ch1", "alice", "key-001", wrapped)

        state.revoke_member("ch1", "carol")

        members = state.get_channel_members("ch1")
        self.assertNotIn("carol", members)
        self.assertIn("alice", members)
        self.assertIn("bob", members)

    def test_revoke_nonexistent_member(self):
        wrapped = {"alice": {"ciphertext": "aa", "iv": "bb"}}
        state.init_channel("ch1", "alice", "key-001", wrapped)
        with self.assertRaises(KeyError):
            state.revoke_member("ch1", "bob")


if __name__ == "__main__":
    unittest.main()

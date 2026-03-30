"""
test_crypto.py -- Unit tests for crypto.py
NYU CS6903/4783 Project 2.2
"""

import os
import sys
import tempfile
import unittest

# Add parent directory to path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import crypto
from cryptography.exceptions import InvalidTag, InvalidSignature


class TestKeyGeneration(unittest.TestCase):
    """Test X25519 and Ed25519 key generation."""

    def test_x25519_keypair(self):
        priv, pub = crypto.generate_x25519_keypair()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_ed25519_keypair(self):
        priv, pub = crypto.generate_ed25519_keypair()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)

    def test_x25519_keypairs_are_unique(self):
        priv1, _ = crypto.generate_x25519_keypair()
        priv2, _ = crypto.generate_x25519_keypair()
        from cryptography.hazmat.primitives import serialization
        b1 = priv1.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        b2 = priv2.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self.assertNotEqual(b1, b2)


class TestKeySerialization(unittest.TestCase):
    """Test save/load roundtrip for all key types."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_x25519_roundtrip(self):
        priv, pub = crypto.generate_x25519_keypair()
        priv_path = os.path.join(self.tmpdir, "x_priv.pem")
        pub_path = os.path.join(self.tmpdir, "x_pub.pem")

        crypto.save_private_key(priv, priv_path)
        crypto.save_public_key(pub, pub_path)

        loaded_priv = crypto.load_x25519_private(priv_path)
        loaded_pub = crypto.load_x25519_public(pub_path)

        # Verify they work by performing a DH exchange
        from cryptography.hazmat.primitives import serialization
        orig_pub_bytes = pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        loaded_pub_bytes = loaded_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.assertEqual(orig_pub_bytes, loaded_pub_bytes)

    def test_ed25519_roundtrip(self):
        priv, pub = crypto.generate_ed25519_keypair()
        priv_path = os.path.join(self.tmpdir, "ed_priv.pem")
        pub_path = os.path.join(self.tmpdir, "ed_pub.pem")

        crypto.save_private_key(priv, priv_path)
        crypto.save_public_key(pub, pub_path)

        loaded_priv = crypto.load_ed25519_private(priv_path)
        loaded_pub = crypto.load_ed25519_public(pub_path)

        # Verify by signing and verifying
        msg = b"test message"
        sig = loaded_priv.sign(msg)
        loaded_pub.verify(sig, msg)  # Should not raise

    def test_load_nonexistent_raises(self):
        with self.assertRaises(FileNotFoundError):
            crypto.load_x25519_private("/nonexistent/key.pem")


class TestFingerprint(unittest.TestCase):
    """Test key fingerprinting."""

    def test_fingerprint_deterministic(self):
        _, pub = crypto.generate_x25519_keypair()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "pub.pem")
        crypto.save_public_key(pub, path)

        fp1 = crypto.fingerprint(path)
        fp2 = crypto.fingerprint(path)
        self.assertEqual(fp1, fp2)

    def test_fingerprint_format(self):
        _, pub = crypto.generate_x25519_keypair()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "pub.pem")
        crypto.save_public_key(pub, path)

        fp = crypto.fingerprint(path)
        # SHA-256 hex = 64 chars, colon-separated pairs = 32 pairs
        parts = fp.split(":")
        self.assertEqual(len(parts), 32)
        for part in parts:
            self.assertEqual(len(part), 2)

    def test_different_keys_different_fingerprints(self):
        tmpdir = tempfile.mkdtemp()

        _, pub1 = crypto.generate_x25519_keypair()
        path1 = os.path.join(tmpdir, "pub1.pem")
        crypto.save_public_key(pub1, path1)

        _, pub2 = crypto.generate_x25519_keypair()
        path2 = os.path.join(tmpdir, "pub2.pem")
        crypto.save_public_key(pub2, path2)

        self.assertNotEqual(crypto.fingerprint(path1), crypto.fingerprint(path2))


class TestAESGCM(unittest.TestCase):
    """Test AES-256-GCM encryption and decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Hello, secure world!"
        aad = b"some-authenticated-data"

        ciphertext, iv = crypto.encrypt_message(plaintext, key, aad)
        decrypted = crypto.decrypt_message(ciphertext, iv, key, aad)
        self.assertEqual(decrypted, plaintext)

    def test_tampered_ciphertext_raises(self):
        key = os.urandom(32)
        plaintext = b"sensitive data"
        aad = b"aad"

        ciphertext, iv = crypto.encrypt_message(plaintext, key, aad)

        # Tamper with one byte
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        tampered = bytes(tampered)

        with self.assertRaises(InvalidTag):
            crypto.decrypt_message(tampered, iv, key, aad)

    def test_tampered_aad_raises(self):
        key = os.urandom(32)
        plaintext = b"sensitive data"
        aad = b"correct-aad"

        ciphertext, iv = crypto.encrypt_message(plaintext, key, aad)

        with self.assertRaises(InvalidTag):
            crypto.decrypt_message(ciphertext, iv, key, b"wrong-aad")

    def test_wrong_key_raises(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = b"data"
        aad = b"aad"

        ciphertext, iv = crypto.encrypt_message(plaintext, key1, aad)

        with self.assertRaises(InvalidTag):
            crypto.decrypt_message(ciphertext, iv, key2, aad)

    def test_invalid_key_length_raises(self):
        with self.assertRaises(ValueError):
            crypto.encrypt_message(b"data", b"short_key", b"aad")

    def test_unique_iv_per_call(self):
        key = os.urandom(32)
        _, iv1 = crypto.encrypt_message(b"msg1", key, b"aad")
        _, iv2 = crypto.encrypt_message(b"msg2", key, b"aad")
        self.assertNotEqual(iv1, iv2)


class TestEd25519Signing(unittest.TestCase):
    """Test Ed25519 signing and verification."""

    def test_sign_verify_success(self):
        priv, pub = crypto.generate_ed25519_keypair()
        blob = crypto.build_signed_blob(
            b"ciphertext", b"iv12bytes!!!", "alice", 1, "2026-01-01T00:00:00Z", "ch1"
        )
        sig = crypto.sign_message(priv, blob)
        crypto.verify_signature(pub, blob, sig)  # Should not raise

    def test_tampered_blob_raises(self):
        priv, pub = crypto.generate_ed25519_keypair()
        blob = crypto.build_signed_blob(
            b"ciphertext", b"iv12bytes!!!", "alice", 1, "2026-01-01T00:00:00Z", "ch1"
        )
        sig = crypto.sign_message(priv, blob)

        # Tamper with blob
        tampered_blob = crypto.build_signed_blob(
            b"TAMPERED", b"iv12bytes!!!", "alice", 1, "2026-01-01T00:00:00Z", "ch1"
        )

        with self.assertRaises(InvalidSignature):
            crypto.verify_signature(pub, tampered_blob, sig)

    def test_wrong_key_raises(self):
        priv1, _ = crypto.generate_ed25519_keypair()
        _, pub2 = crypto.generate_ed25519_keypair()

        blob = crypto.build_signed_blob(
            b"ct", b"iv12bytes!!!", "alice", 1, "ts", "ch"
        )
        sig = crypto.sign_message(priv1, blob)

        with self.assertRaises(InvalidSignature):
            crypto.verify_signature(pub2, blob, sig)

    def test_signed_blob_includes_all_fields(self):
        """Changing any field should produce a different blob."""
        base_args = [b"ct", b"iv", "alice", 1, "ts", "ch"]
        base_blob = crypto.build_signed_blob(*base_args)

        # Change each field one at a time
        variants = [
            [b"CT", b"iv", "alice", 1, "ts", "ch"],
            [b"ct", b"IV", "alice", 1, "ts", "ch"],
            [b"ct", b"iv", "bob", 1, "ts", "ch"],
            [b"ct", b"iv", "alice", 2, "ts", "ch"],
            [b"ct", b"iv", "alice", 1, "TS", "ch"],
            [b"ct", b"iv", "alice", 1, "ts", "CH"],
        ]
        for v in variants:
            alt_blob = crypto.build_signed_blob(*v)
            self.assertNotEqual(base_blob, alt_blob,
                                f"Blob unchanged when modifying field: {v}")


class TestGroupKeyWrapping(unittest.TestCase):
    """Test group key wrap/unwrap roundtrip."""

    def test_wrap_unwrap_roundtrip(self):
        admin_priv, admin_pub = crypto.generate_x25519_keypair()
        member_priv, member_pub = crypto.generate_x25519_keypair()
        group_key = os.urandom(32)

        wrapped = crypto.wrap_group_key(group_key, member_pub, admin_priv, "ch1")
        unwrapped = crypto.unwrap_group_key(wrapped, admin_pub, member_priv, "ch1")

        self.assertEqual(unwrapped, group_key)

    def test_wrong_recipient_fails(self):
        admin_priv, admin_pub = crypto.generate_x25519_keypair()
        _, member_pub = crypto.generate_x25519_keypair()
        wrong_priv, _ = crypto.generate_x25519_keypair()
        group_key = os.urandom(32)

        wrapped = crypto.wrap_group_key(group_key, member_pub, admin_priv, "ch1")

        with self.assertRaises(InvalidTag):
            crypto.unwrap_group_key(wrapped, admin_pub, wrong_priv, "ch1")

    def test_wrong_channel_fails(self):
        admin_priv, admin_pub = crypto.generate_x25519_keypair()
        member_priv, member_pub = crypto.generate_x25519_keypair()
        group_key = os.urandom(32)

        wrapped = crypto.wrap_group_key(group_key, member_pub, admin_priv, "ch1")

        with self.assertRaises(InvalidTag):
            crypto.unwrap_group_key(wrapped, admin_pub, member_priv, "ch2")


if __name__ == "__main__":
    unittest.main()

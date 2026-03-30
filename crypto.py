"""
crypto.py -- All cryptographic operations for E2E encrypted Slack messaging.
NYU CS6903/4783 Project 2.2

This module contains ZERO Slack API calls and ZERO side effects (no prints,
no file writes except through explicit save functions). Every function raises
explicit exceptions on failure.

Primitives used:
    - AES-256-GCM     (authenticated encryption)
    - X25519 ECDH     (key agreement)
    - HKDF-SHA256     (key derivation)
    - Ed25519         (digital signatures)
"""

import os
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag, InvalidSignature  # noqa: F401


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------

def generate_x25519_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 keypair for Diffie-Hellman key agreement.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def generate_ed25519_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair for digital signatures.

    Returns:
        Tuple of (private_key, public_key).
    """
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Key Serialization
# ---------------------------------------------------------------------------

def save_private_key(key, path: str) -> None:
    """Save a private key to PEM format (PKCS8, no encryption).

    Args:
        key: An X25519PrivateKey or Ed25519PrivateKey.
        path: Filesystem path to write.
    """
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem_bytes)


def save_public_key(key, path: str) -> None:
    """Save a public key to PEM format (SubjectPublicKeyInfo).

    Args:
        key: An X25519PublicKey or Ed25519PublicKey.
        path: Filesystem path to write.
    """
    pem_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_x25519_private(path: str) -> X25519PrivateKey:
    """Load an X25519 private key from a PEM file.

    Args:
        path: Path to the PEM file.

    Returns:
        X25519PrivateKey instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file does not contain a valid X25519 private key.
    """
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError(f"{path} does not contain an X25519 private key")
    return key


def load_x25519_public(path: str) -> X25519PublicKey:
    """Load an X25519 public key from a PEM file.

    Args:
        path: Path to the PEM file.

    Returns:
        X25519PublicKey instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file does not contain a valid X25519 public key.
    """
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, X25519PublicKey):
        raise ValueError(f"{path} does not contain an X25519 public key")
    return key


def load_ed25519_private(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file.

    Args:
        path: Path to the PEM file.

    Returns:
        Ed25519PrivateKey instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file does not contain a valid Ed25519 private key.
    """
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} does not contain an Ed25519 private key")
    return key


def load_ed25519_public(path: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file.

    Args:
        path: Path to the PEM file.

    Returns:
        Ed25519PublicKey instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file does not contain a valid Ed25519 public key.
    """
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} does not contain an Ed25519 public key")
    return key


# ---------------------------------------------------------------------------
# Key Fingerprinting
# ---------------------------------------------------------------------------

def fingerprint(public_key_path: str) -> str:
    """Compute the SHA-256 fingerprint of a public key file.

    Used for out-of-band key verification. Members read fingerprints
    aloud over a trusted channel to detect MITM key substitution.

    Args:
        public_key_path: Path to a PEM-encoded public key.

    Returns:
        Colon-separated hex string, e.g. "4a:bf:c3:d9:12:..."
    """
    with open(public_key_path, "rb") as f:
        key_bytes = f.read()
    digest = hashlib.sha256(key_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


# ---------------------------------------------------------------------------
# Key Derivation (ECDH + HKDF)
# ---------------------------------------------------------------------------

def derive_wrapping_key(
    my_private_x25519: X25519PrivateKey,
    peer_public_x25519: X25519PublicKey,
    channel_id: str,
    context: str = "",
) -> bytes:
    """Derive a 256-bit key from an X25519 DH exchange followed by HKDF.

    The raw X25519 output is NOT uniformly distributed; HKDF is mandatory.
    The channel_id as HKDF info ensures keys are domain-separated per channel.

    Args:
        my_private_x25519: Our X25519 private key.
        peer_public_x25519: Peer's X25519 public key.
        channel_id: Channel identifier for domain separation.
        context: Optional extra context appended to the info string
                 (e.g. ":wrap" for key-wrapping operations).

    Returns:
        32-byte derived key.
    """
    shared_secret = my_private_x25519.exchange(peer_public_x25519)
    info = (channel_id + context).encode("utf-8")
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt_message(
    plaintext: bytes, aes_key: bytes, aad: bytes
) -> Tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM.

    The 16-byte GCM authentication tag is appended to the ciphertext
    automatically by the cryptography library.

    Args:
        plaintext: Data to encrypt.
        aes_key: 32-byte AES key.
        aad: Additional Authenticated Data (included in tag computation
             but not encrypted).

    Returns:
        Tuple of (ciphertext_with_tag, iv).
        The IV is a 96-bit random nonce generated fresh for this message.

    Raises:
        ValueError: If the AES key is not 32 bytes.
    """
    if len(aes_key) != 32:
        raise ValueError("AES key must be exactly 32 bytes")
    iv = os.urandom(12)  # 96-bit nonce -- MUST be fresh per message
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    return ciphertext_with_tag, iv


def decrypt_message(
    ciphertext_with_tag: bytes, iv: bytes, aes_key: bytes, aad: bytes
) -> bytes:
    """Decrypt AES-256-GCM ciphertext and verify the authentication tag.

    Args:
        ciphertext_with_tag: Ciphertext with appended 16-byte GCM tag.
        iv: The 96-bit nonce used during encryption.
        aes_key: 32-byte AES key.
        aad: Additional Authenticated Data (must match encryption-time AAD).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If the ciphertext or AAD has
            been tampered with. Callers MUST handle this.
    """
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext_with_tag, aad)


# ---------------------------------------------------------------------------
# Ed25519 Signing
# ---------------------------------------------------------------------------

def build_signed_blob(
    ciphertext_with_tag: bytes,
    iv: bytes,
    sender_id: str,
    sequence: int,
    timestamp: str,
    channel_id: str,
) -> bytes:
    """Build the blob to be signed/verified.

    All fields are concatenated with a 0x00 separator to prevent field
    confusion attacks, then hashed with SHA-256. Every field that an
    attacker could swap or modify is included.

    We sign the ciphertext (not the plaintext) so that an attacker cannot
    strip the signature, re-encrypt under a different key, and reattach
    the original valid signature.

    Args:
        ciphertext_with_tag: The AES-GCM ciphertext including the tag.
        iv: The 96-bit nonce.
        sender_id: Identifier of the sender.
        sequence: Monotonic sequence number for replay prevention.
        timestamp: ISO-8601 timestamp string.
        channel_id: Channel identifier.

    Returns:
        32-byte SHA-256 digest of the concatenated fields.
    """
    separator = b"\x00"
    blob = separator.join([
        ciphertext_with_tag,
        iv,
        sender_id.encode("utf-8"),
        str(sequence).encode("utf-8"),
        timestamp.encode("utf-8"),
        channel_id.encode("utf-8"),
    ])
    return hashlib.sha256(blob).digest()


def sign_message(private_key: Ed25519PrivateKey, signed_blob: bytes) -> bytes:
    """Sign a blob with Ed25519.

    Args:
        private_key: The sender's Ed25519 private key.
        signed_blob: The 32-byte digest to sign (from build_signed_blob).

    Returns:
        64-byte Ed25519 signature.
    """
    return private_key.sign(signed_blob)


def verify_signature(
    public_key: Ed25519PublicKey, signed_blob: bytes, signature: bytes
) -> None:
    """Verify an Ed25519 signature.

    Args:
        public_key: The claimed sender's Ed25519 public key.
        signed_blob: The 32-byte digest (reconstructed by the verifier).
        signature: The 64-byte Ed25519 signature.

    Raises:
        cryptography.exceptions.InvalidSignature: If verification fails.
    """
    public_key.verify(signature, signed_blob)


# ---------------------------------------------------------------------------
# Group Key Wrapping / Unwrapping
# ---------------------------------------------------------------------------

def wrap_group_key(
    group_aes_key: bytes,
    recipient_x25519_public: X25519PublicKey,
    my_x25519_private: X25519PrivateKey,
    channel_id: str,
) -> dict:
    """Wrap (encrypt) a group AES key for a specific recipient.

    Uses ECDH + HKDF with info = channel_id + ":wrap" to derive a
    per-recipient wrapping key, then AES-256-GCM encrypts the group key.

    Args:
        group_aes_key: The 32-byte group AES key to wrap.
        recipient_x25519_public: Recipient's X25519 public key.
        my_x25519_private: Admin's X25519 private key.
        channel_id: Channel identifier for domain separation.

    Returns:
        Dict with 'ciphertext' and 'iv' as hex strings.
    """
    wrapping_key = derive_wrapping_key(
        my_x25519_private, recipient_x25519_public, channel_id, context=":wrap"
    )
    ciphertext, iv = encrypt_message(group_aes_key, wrapping_key, aad=b"")
    return {"ciphertext": ciphertext.hex(), "iv": iv.hex()}


def unwrap_group_key(
    wrapped: dict,
    sender_x25519_public: X25519PublicKey,
    my_x25519_private: X25519PrivateKey,
    channel_id: str,
) -> bytes:
    """Unwrap (decrypt) a group AES key.

    Performs the inverse of wrap_group_key using ECDH + HKDF.

    Args:
        wrapped: Dict with 'ciphertext' and 'iv' as hex strings.
        sender_x25519_public: Admin's X25519 public key.
        my_x25519_private: Recipient's X25519 private key.
        channel_id: Channel identifier for domain separation.

    Returns:
        The 32-byte group AES key.

    Raises:
        cryptography.exceptions.InvalidTag: If unwrapping fails.
    """
    wrapping_key = derive_wrapping_key(
        my_x25519_private, sender_x25519_public, channel_id, context=":wrap"
    )
    ciphertext = bytes.fromhex(wrapped["ciphertext"])
    iv = bytes.fromhex(wrapped["iv"])
    return decrypt_message(ciphertext, iv, wrapping_key, aad=b"")

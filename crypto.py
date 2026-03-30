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


def generate_x25519_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def generate_ed25519_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_private_key(key, path: str) -> None:
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem_bytes)


def save_public_key(key, path: str) -> None:
    pem_bytes = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem_bytes)


def load_x25519_private(path: str) -> X25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError(f"{path} does not contain an X25519 private key")
    return key


def load_x25519_public(path: str) -> X25519PublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, X25519PublicKey):
        raise ValueError(f"{path} does not contain an X25519 public key")
    return key


def load_ed25519_private(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} does not contain an Ed25519 private key")
    return key


def load_ed25519_public(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_public_key(f.read())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} does not contain an Ed25519 public key")
    return key


def fingerprint(public_key_path: str) -> str:
    with open(public_key_path, "rb") as f:
        key_bytes = f.read()
    digest = hashlib.sha256(key_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def derive_wrapping_key(
    my_private_x25519: X25519PrivateKey,
    peer_public_x25519: X25519PublicKey,
    channel_id: str,
    context: str = "",
) -> bytes:
    shared_secret = my_private_x25519.exchange(peer_public_x25519)
    info = (channel_id + context).encode("utf-8")
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived


def encrypt_message(
    plaintext: bytes, aes_key: bytes, aad: bytes
) -> Tuple[bytes, bytes]:
    if len(aes_key) != 32:
        raise ValueError("AES key must be exactly 32 bytes")
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, aad)
    return ciphertext_with_tag, iv


def decrypt_message(
    ciphertext_with_tag: bytes, iv: bytes, aes_key: bytes, aad: bytes
) -> bytes:
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext_with_tag, aad)


def build_signed_blob(
    ciphertext_with_tag: bytes,
    iv: bytes,
    sender_id: str,
    sequence: int,
    timestamp: str,
    channel_id: str,
) -> bytes:
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
    return private_key.sign(signed_blob)


def verify_signature(
    public_key: Ed25519PublicKey, signed_blob: bytes, signature: bytes
) -> None:
    public_key.verify(signature, signed_blob)


def wrap_group_key(
    group_aes_key: bytes,
    recipient_x25519_public: X25519PublicKey,
    my_x25519_private: X25519PrivateKey,
    channel_id: str,
) -> dict:
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
    wrapping_key = derive_wrapping_key(
        my_x25519_private, sender_x25519_public, channel_id, context=":wrap"
    )
    ciphertext = bytes.fromhex(wrapped["ciphertext"])
    iv = bytes.fromhex(wrapped["iv"])
    return decrypt_message(ciphertext, iv, wrapping_key, aad=b"")

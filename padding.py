"""
padding.py -- Optional message padding for traffic analysis mitigation.
NYU CS6903/4783 Project 2.2

Pads plaintext to a fixed block size so that an observer cannot distinguish
short acknowledgments from long incident reports based on ciphertext length.

Uses a 4-byte big-endian length prefix followed by the plaintext and then
zero-byte padding to the next block boundary. This approach supports block
sizes larger than 255 (unlike PKCS7 which is limited to single-byte padding
values).

Activated with the --pad flag on the post command.
"""

import struct


def pad_message(plaintext: bytes, block_size: int = 512) -> bytes:
    """Pad plaintext to the next multiple of block_size.

    Format: [4-byte big-endian length][plaintext][zero padding]
    Total length is always a multiple of block_size.

    Args:
        plaintext: Raw message bytes.
        block_size: Target block size in bytes (default 512).

    Returns:
        Padded bytes whose length is a multiple of block_size.

    Raises:
        ValueError: If block_size is less than 5 (must fit the 4-byte
                    length prefix plus at least one byte).
        ValueError: If plaintext is too large (length exceeds 2^32 - 1).
    """
    if block_size < 5:
        raise ValueError("block_size must be at least 5")
    if len(plaintext) > 0xFFFFFFFF:
        raise ValueError("Plaintext too large for 4-byte length prefix")

    # Prepend 4-byte length
    data = struct.pack(">I", len(plaintext)) + plaintext

    # Pad to next multiple of block_size
    remainder = len(data) % block_size
    if remainder != 0:
        padding_needed = block_size - remainder
    else:
        # Already aligned, but add a full block so padding is never zero
        # (ensures the format is always unambiguous)
        padding_needed = block_size

    return data + b"\x00" * padding_needed


def unpad_message(padded: bytes) -> bytes:
    """Remove length-prefix padding.

    Reads the 4-byte big-endian length prefix and extracts exactly
    that many bytes of plaintext.

    Args:
        padded: Padded message bytes.

    Returns:
        Original plaintext with padding removed.

    Raises:
        ValueError: If the data is too short or the length is invalid.
    """
    if len(padded) < 4:
        raise ValueError("Padded data too short (need at least 4-byte header)")

    (original_len,) = struct.unpack(">I", padded[:4])
    if original_len > len(padded) - 4:
        raise ValueError(
            f"Invalid length prefix: claims {original_len} bytes "
            f"but only {len(padded) - 4} available"
        )

    return padded[4 : 4 + original_len]

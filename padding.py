import struct


def pad_message(plaintext: bytes, block_size: int = 512) -> bytes:
    if block_size < 5:
        raise ValueError("block_size must be at least 5")
    if len(plaintext) > 0xFFFFFFFF:
        raise ValueError("Plaintext too large for 4-byte length prefix")

    data = struct.pack(">I", len(plaintext)) + plaintext

    remainder = len(data) % block_size
    if remainder != 0:
        padding_needed = block_size - remainder
    else:
        padding_needed = block_size

    return data + b"\x00" * padding_needed


def unpad_message(padded: bytes) -> bytes:
    if len(padded) < 4:
        raise ValueError("Padded data too short (need at least 4-byte header)")

    (original_len,) = struct.unpack(">I", padded[:4])
    if original_len > len(padded) - 4:
        raise ValueError(
            f"Invalid length prefix: claims {original_len} bytes "
            f"but only {len(padded) - 4} available"
        )

    return padded[4 : 4 + original_len]

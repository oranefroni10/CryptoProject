def make_key(passphrase: str, length: int = 16) -> bytes:
    """
    Derive a fixed‑length key from an arbitrary pass‑phrase.
    Simple XOR folding.
    """
    key = bytearray(length)
    for i, ch in enumerate(passphrase.encode()):
        key[i % length] ^= ch
    return bytes(key)


def xor(block: bytearray, offset: int, iv: bytes) -> None:
    for i in range(len(iv)):
        block[offset + i] ^= iv[i]


def concat16(b1: int, b2: int) -> int:
    return ((b1 & 0xFF) << 8) | (b2 & 0xFF)

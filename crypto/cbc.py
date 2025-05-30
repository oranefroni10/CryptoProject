from __future__ import annotations
from crypto.idea import IDEA
from crypto.utils import xor
from crypto.utils import make_key


class CBC:
    """Classic CBC mode wrapping any 64‑bit block cipher."""

    def __init__(self, passphrase: str, encrypt: bool):
        self.cipher = IDEA(passphrase, encrypt)
        self.encrypt = encrypt
        self.block = self.cipher.block_size
        self.iv = bytearray(make_key(passphrase, self.block))

    def process(self, chunk: bytes) -> bytes:
        buf = bytearray(chunk)
        if self.encrypt:
            xor(buf, 0, self.iv)
            self.cipher.crypt_block(buf)
            self.iv[:] = buf
        else:
            tmp = buf[:]
            self.cipher.crypt_block(buf)
            xor(buf, 0, self.iv)
            self.iv[:] = tmp
        return bytes(buf)

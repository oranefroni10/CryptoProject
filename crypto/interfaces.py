from abc import ABC, abstractmethod


class BlockCipher(ABC):
    """Interface for 64‑bit block ciphers with 128‑bit keys."""

    block_size: int = 8
    key_size: int = 16

    @abstractmethod
    def set_key(self, key: bytes) -> None: ...

    @abstractmethod
    def crypt_block(self, data: bytearray, offset: int = 0) -> None: ...

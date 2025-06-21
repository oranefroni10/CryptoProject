# FILE: core/key_exchange.py
"""
Simple Merkle–Hellman super‑increasing knapsack to wrap the 128‑bit IDEA key.
Not cryptographically strong for real use – fits the course requirement.
"""
import random
from math import gcd
from typing import List, Tuple
from hashlib import sha256 # Added for deterministic seeding if used with _mhk helper


def _inv_mod(a, m):
    """Calculates the modular multiplicative inverse of a modulo m."""
    # pow(a, -1, m) computes a raised to the power of -1 modulo m,
    # which is equivalent to modular inverse.
    return pow(a, -1, m)


class MHK:
    """
    Merkle-Hellman Knapsack cryptosystem for wrapping a 128-bit key.
    Generates a super-increasing sequence (private key) and a corresponding public key.
    """
    def __init__(self, n: int = 128):
        """
        Initializes the Merkle-Hellman knapsack with 'n' bits.
        'n' should typically be 128 for a 128-bit key.
        """
        self._w = [0] * n  # Super-increasing sequence (private key component)

        # Generate a truly super-increasing sequence.
        # Each element w_k must be strictly greater than the sum of all previous elements.
        # This method ensures a robust super-increasing property by adding a random offset
        # to the current sum, making w_k significantly larger than the previous sum.
        self._w[0] = random.randint(1, 100) # Start with a small, positive random integer
        current_sum = self._w[0]
        for i in range(1, n):
            # w_i = (sum of previous w's) + (random_positive_offset)
            # This ensures w_i > sum of previous w's
            self._w[i] = current_sum + random.randint(1, 500)
            current_sum += self._w[i]

        # Choose 'q': a modulus that must be greater than the sum of all elements in _w.
        # A larger 'q' (e.g., up to 2*sum(w)) can help spread out the values in the public key
        # and improve the reliability of the modular arithmetic.
        self._q = random.randint(current_sum + 1, current_sum * 2)
        # Fallback if random choice somehow yields a q that's not strictly greater (unlikely but safe)
        if self._q <= current_sum:
             self._q = current_sum + 1

        # Choose 'r': a multiplier, 1 < r < q, such that gcd(r, q) = 1.
        # 'r' must be coprime to 'q' to have a modular inverse.
        self._r = random.randrange(2, self._q)
        while gcd(self._r, self._q) != 1:
            self._r = random.randrange(2, self._q)

        # Calculate the public key components: P_k = (r * w_k) mod q
        self.public = [(self._r * w) % self._q for w in self._w]

    # ---------------- encryption / decryption ----------------
    def encrypt(self, key: bytes) -> int:
        """
        Encrypts a 128-bit key (16 bytes) using the Merkle-Hellman public key.
        The key is treated as a 128-bit binary string.
        """
        if len(key) != 16:
            raise ValueError(f"Key for encryption must be 128 bits (16 bytes), but got {len(key)} bytes.")

        # Convert the 16-byte key into a 128-character binary string.
        # f'{b:08b}' formats each byte 'b' into an 8-bit binary string, padding with leading zeros if necessary.
        bits = ''.join(f'{b:08b}' for b in key)

        # Encrypt the key by summing selected public key elements.
        # If the i-th bit of the key is '1', add the i-th public key element.
        s = sum(int(bit) * pk_element for bit, pk_element in zip(bits, self.public))
        return s

    def decrypt(self, s: int) -> bytes:
        """
        Decrypts an integer ciphertext 's' back to the original 128-bit key
        using the Merkle-Hellman private key components.
        """
        # Calculate the modular inverse of 'r' modulo 'q'.
        r_inv = _inv_mod(self._r, self._q)

        # Transform the ciphertext 's' back into the original sum 'M' from the super-increasing knapsack.
        # M = (s * r_inv) mod q
        total = (s * r_inv) % self._q

        # Initialize a list to hold the decrypted bits (0s and 1s).
        # Its length is 'n' (128 for a 128-bit key).
        bits: List[int] = [0] * len(self._w)

        # Reconstruct the original message bits using the greedy algorithm.
        # Iterate through the super-increasing sequence 'w' from largest to smallest.
        # If 'total' is greater than or equal to the current w_i, it means the corresponding bit was '1'.
        # Subtract w_i from 'total' and set the bit to '1'.
        for i in reversed(range(len(self._w))): # Iterate from n-1 down to 0 (largest weight to smallest)
            if total >= self._w[i]:
                bits[i] = 1        # Set the i-th bit to 1
                total -= self._w[i] # Subtract the corresponding weight from the total

        # Convert the list of integers (0s and 1s) representing bits into a single binary string.
        # The 'bits' list is correctly ordered from MSB (bits[0]) to LSB (bits[n-1]).
        bitstr = ''.join(map(str, bits))

        # Convert the 128-bit binary string back into 16 bytes.
        # This is done by taking 8-bit (1-byte) chunks and converting them from binary to integer.
        byts = [int(bitstr[i:i + 8], 2) for i in range(0, len(bitstr), 8)]

        # Return the resulting 16 bytes (128-bit) key.
        return bytes(byts)
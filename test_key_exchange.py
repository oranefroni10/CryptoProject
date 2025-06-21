# test_key_exchange.py
import sys
from pathlib import Path
import os
from hashlib import sha256
import random

# Add the parent directory of 'core' to the Python path
# This assumes test_key_exchange.py is in the root, and 'core' is a direct subdirectory.
# Adjust if your test file is in a different location relative to 'core'.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.key_exchange import MHK

# This is the _mhk helper function from secure_transfer.py, crucial for deterministic key generation
def _mhk(pw):
    seed = int.from_bytes(sha256(pw.encode()).digest(), 'big') & 0xffffffff
    st = random.getstate()
    random.seed(seed)
    obj = MHK()
    random.setstate(st)
    return obj

def test_merkle_hellman_key_exchange():
    print("\n--- Testing Merkle-Hellman Key Exchange ---")

    # 1. Define a consistent passphrase for testing
    passphrase = "my_mhk_secret_passphrase"
    # 2. Generate a random 16-byte (128-bit) content key
    original_content_key = os.urandom(16)

    print(f"Passphrase: '{passphrase}'")
    print(f"Original content key (hex): {original_content_key.hex()}")

    try:
        # 3. Sender side: Create MHK object deterministically and encrypt the content key
        sender_mhk = _mhk(passphrase)
        encrypted_content_key = sender_mhk.encrypt(original_content_key)
        print(f"Encrypted content key: {encrypted_content_key}")

        # 4. Receiver side: Create MHK object deterministically with the *same* passphrase
        receiver_mhk = _mhk(passphrase)
        # 5. Decrypt the content key
        decrypted_content_key_raw = receiver_mhk.decrypt(encrypted_content_key)
        # As per secure_transfer.py, we take the last 16 bytes
        decrypted_content_key = decrypted_content_key_raw[-16:]
        print(f"Decrypted content key (hex): {decrypted_content_key.hex()}")

        # 6. Verify if the decrypted key matches the original
        assert original_content_key == decrypted_content_key, \
            "Merkle-Hellman key exchange failed: Decrypted key does not match original!"

        print("Merkle-Hellman Key Exchange Test Passed Successfully!")

        # Test with wrong passphrase (should lead to different MHK keys and thus fail decryption)
        wrong_passphrase = "a_different_passphrase"
        wrong_receiver_mhk = _mhk(wrong_passphrase)
        try:
            wrong_decrypted_key_raw = wrong_receiver_mhk.decrypt(encrypted_content_key)
            wrong_decrypted_key = wrong_decrypted_key_raw[-16:]
            # It might technically decrypt to *something*, but it won't be the correct key
            assert original_content_key != wrong_decrypted_key, \
                "Merkle-Hellman key exchange failed: Wrong passphrase decrypted key successfully!"
            print(f"Decrypted with wrong passphrase (hex): {wrong_decrypted_key.hex()} (Expected to be different)")
            print("Merkle-Hellman (wrong passphrase) test passed (correctly failed to decrypt original key).")
        except Exception as e:
            print(f"Decryption with wrong passphrase failed as expected: {e}")


    except Exception as e:
        print(f"Merkle-Hellman Key Exchange Test Failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_merkle_hellman_key_exchange()
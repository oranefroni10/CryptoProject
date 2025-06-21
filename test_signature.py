# test_signature.py
import sys
from pathlib import Path

# Add the parent directory of 'core' to the Python path
# This assumes test_signature.py is in the root, and 'core' is a direct subdirectory.
# Adjust if your test file is in a different location relative to 'core'.
sys.path.insert(0, str(Path(__file__).resolve().parent))


from core.signature import ECDSA

def test_ecdsa_signature():
    print("\n--- Testing ECDSA Signature ---")

    # 1. Define a consistent passphrase for testing
    passphrase = "my_super_secure_passphrase_for_testing"
    message_data = b"Hello, this is a test message to be signed."

    print(f"Passphrase: '{passphrase}'")
    print(f"Message: '{message_data.decode()}'")

    try:
        # 2. Create an ECDSA signer instance (implicitly generates private and public keys)
        signer = ECDSA(passphrase)
        print(f"Signer Public Key (Q): {signer.Q}")

        # 3. Sign the message
        signature = signer.sign(message_data)
        r, s = signature
        print(f"Generated Signature (r, s): ({r}, {s})")

        # 4. Verify the signature using the *same* message and the signer's public key
        is_valid = ECDSA.verify(message_data, signature, signer.Q)
        print(f"Signature verification (same signer): {is_valid}")
        assert is_valid == True, "Self-verification failed!"

        # 5. Test with a different message (should fail verification)
        tampered_message = b"Hello, this is a tampered message."
        is_valid_tampered = ECDSA.verify(tampered_message, signature, signer.Q)
        print(f"Signature verification (tampered message): {is_valid_tampered}")
        assert is_valid_tampered == False, "Tampered message verification passed unexpectedly!"

        # 6. Test with a different passphrase (should fail verification if public key changes)
        # Note: The public key is part of the header in your secure_transfer,
        # so if the *sender's* passphrase changes, the *sent* public key will change.
        # But here, we're testing the integrity of the algorithm itself.
        wrong_passphrase = "wrong_passphrase"
        wrong_signer = ECDSA(wrong_passphrase)
        print(f"Wrong Signer Public Key (Q'): {wrong_signer.Q}")
        # This test assumes the verification uses the *original* signer.Q
        is_valid_wrong_key = ECDSA.verify(message_data, signature, wrong_signer.Q)
        print(f"Signature verification (wrong public key): {is_valid_wrong_key}")
        assert is_valid_wrong_key == False, "Verification with wrong public key passed unexpectedly!"


        print("ECDSA Signature Test Passed Successfully!")

    except Exception as e:
        print(f"ECDSA Signature Test Failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ecdsa_signature()
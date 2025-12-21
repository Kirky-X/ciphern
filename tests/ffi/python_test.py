import unittest
from ciphern import Ciphern

class TestCiphern(unittest.TestCase):
    def setUp(self):
        self.ciphern = Ciphern()

    def test_encrypt_decrypt(self):
        print("Running Python FFI Test...")
        algorithm = "AES256GCM"
        key_id = self.ciphern.generate_key(algorithm)
        self.assertIsNotNone(key_id)
        self.assertNotEqual(key_id, "")
        print(f"Generated key ID: {key_id}")

        plaintext = b"Hello from Python PyO3!"
        ciphertext = self.ciphern.encrypt(key_id, plaintext)
        self.assertIsNotNone(ciphertext)
        self.assertGreater(len(ciphertext), 0)
        print("Encryption successful")

        decrypted = self.ciphern.decrypt(key_id, ciphertext)
        self.assertEqual(plaintext, bytes(decrypted))
        print(f"Decryption successful: {bytes(decrypted).decode('utf-8')}")
        print("Python FFI Test Passed!")

    def test_context_manager(self):
        with Ciphern() as c:
            key_id = c.generate_key("AES256GCM")
            self.assertIsNotNone(key_id)

if __name__ == '__main__':
    unittest.main()

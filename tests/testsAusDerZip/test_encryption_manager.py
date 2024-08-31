import unittest
import sys
import os

# Füge das Verzeichnis eine Ebene höher zum Python-Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import EncryptionManager

class TestEncryptionManager(unittest.TestCase):

    def setUp(self):
        self.key = "securepassword"
        self.encryption_manager = EncryptionManager(self.key)

    def test_encrypt_decrypt(self):
        plaintext = "Hello, World!"
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_empty_string(self):
        plaintext = ""
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_special_characters(self):
        plaintext = "!@#$%^&*()_+-=~`[]{}|;:'\",.<>?/\\"
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_large_string(self):
        plaintext = "a" * 10000
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_special_characters(self):
        plaintext = "Hello, 世界! 👋"
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            EncryptionManager(12345)

    def test_invalid_decryption_input(self):
        with self.assertRaises(Exception):
            self.encryption_manager.decrypt("not a valid encrypted text")

    def test_different_keys(self):
        plaintext = "Sensitive data"
        ciphertext = self.encryption_manager.encrypt(plaintext)
        
        wrong_key_manager = EncryptionManager("wrongpassword")
        with self.assertRaises(Exception):
            wrong_key_manager.decrypt(ciphertext)

    def test_encrypt_binary_data(self):
        plaintext = bytes(range(256))  # Alle möglichen Byte-Werte
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

if __name__ == "__main__":
    unittest.main()

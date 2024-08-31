import unittest
import sys
import os
from unittest.mock import patch, mock_open

# Füge das Verzeichnis eine Ebene höher zum Python-Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import PasswordDatabase, EncryptionManager

class TestPasswordDatabase(unittest.TestCase):

    def setUp(self):
        self.encryption_manager = EncryptionManager("securepassword")
        self.database = PasswordDatabase('test_passwords.json', self.encryption_manager)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def test_initialize_with_missing_file(self, mock_exists, mock_open):
        with self.assertRaises(FileNotFoundError):
            PasswordDatabase('missing_file.json', self.encryption_manager)

    def test_add_and_retrieve_password(self):
        self.database.addPassword('service1', 'user1', 'pass1', 'note1')
        result = self.database.retrievePassword('service1')
        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'user1')
        self.assertEqual(result['password'], 'pass1')
        self.assertEqual(result['note'], 'note1')

    def test_delete_password(self):
        self.database.addPassword('service1', 'user1', 'pass1', 'note1')
        delete_result = self.database.deletePassword('service1')
        self.assertTrue(delete_result)
        result = self.database.retrievePassword('service1')
        self.assertIsNone(result)

    def test_add_password_empty_service_name(self):
        with self.assertRaises(ValueError):
            self.database.addPassword('', 'user1', 'pass1', 'note1')

    def test_add_password_empty_username(self):
        with self.assertRaises(ValueError):
            self.database.addPassword('service1', '', 'pass1', 'note1')

    def test_add_password_empty_password(self):
        with self.assertRaises(ValueError):
            self.database.addPassword('service1', 'user1', '', 'note1')

    def test_retrieve_password_nonexistent_service(self):
        result = self.database.retrievePassword('nonexistent')
        self.assertIsNone(result)

    def test_delete_password_nonexistent_service(self):
        result = self.database.deletePassword('nonexistent')
        self.assertFalse(result)

    def test_is_instance_nonexistent_service(self):
        result = self.database.isInstance('nonexistent')
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()

import unittest
import sys
import os
from unittest.mock import patch, mock_open
import hashlib

# Füge das Verzeichnis eine Ebene höher zum Python-Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import UserManager

class TestUserManager(unittest.TestCase):

    @patch('os.path.exists', return_value=False)
    def test_initialize_with_missing_file(self, mock_exists):
        with self.assertRaises(FileNotFoundError):
            UserManager('missing_file.json')

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    def test_create_user(self, mock_open):
        manager = UserManager('test_users.json')
        result = manager.createUser('testuser', 'password')
        self.assertTrue(result)
        self.assertIn('testuser', manager.users)
        encoded_password = hashlib.sha256(b'password').hexdigest()
        self.assertEqual(manager.users['testuser']['masterPassword'], encoded_password)

        result = manager.createUser('testuser', 'newpassword')
        self.assertFalse(result)

    def test_create_user_with_empty_password(self):
        manager = UserManager('test_users.json')
        with self.assertRaises(ValueError):
            manager.createUser('testuser', '')

    @patch('builtins.open', new_callable=mock_open, read_data='{"testuser": {"masterPassword": "cGFzc3dvcmQ="}}')
    @patch('os.path.exists', return_value=True)
    def test_authenticate(self, mock_exists, mock_open):
        manager = UserManager('test_users.json')
        auth_result = manager.authenticate('testuser', 'password')
        self.assertTrue(auth_result)

        auth_result = manager.authenticate('testuser', 'wrongpassword')
        self.assertFalse(auth_result)

        auth_result = manager.authenticate('nonexistentuser', 'password')
        self.assertFalse(auth_result)

    def test_authenticate_with_empty_password(self):
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        auth_result = manager.authenticate('testuser', '')
        self.assertFalse(auth_result)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_get_user_password(self, mock_exists, mock_open):
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        retrieved_password = manager.getUserPassword('testuser')
        self.assertEqual(retrieved_password, hashlib.sha256(b'password').digest())

        retrieved_password = manager.getUserPassword('nonexistentuser')
        self.assertIsNone(retrieved_password)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_save_load_users(self, mock_exists, mock_open):
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        manager.saveUsers()

        mock_open.assert_called_with('test_users.json', 'w', encoding="utf-8")
        mock_open().write.assert_called_once()

        manager.loadUsers()
        mock_open.assert_called_with('test_users.json', 'r', encoding="utf-8")
        self.assertIn('testuser', manager.users)

    def test_get_user_password_for_nonexistent_user(self):
        manager = UserManager('test_users.json')
        result = manager.getUserPassword('nonexistentuser')
        self.assertIsNone(result)

    def test_create_duplicate_user(self):
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        result = manager.createUser('testuser', 'newpassword')
        self.assertFalse(result)

    def test_invalid_password_format(self):
        manager = UserManager('test_users.json')
        with self.assertRaises(TypeError):
            manager.createUser('testuser', 12345)  # Passwort sollte ein String sein

    @patch('os.path.exists', return_value=True)
    def test_incorrect_password_hash(self, mock_exists):
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        manager.users['testuser']['masterPassword'] = 'incorrect_hash'
        auth_result = manager.authenticate('testuser', 'password')
        self.assertFalse(auth_result)

if __name__ == "__main__":
    unittest.main()

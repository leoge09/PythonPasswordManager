import unittest
import os
import tempfile
import base64
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unittest.mock import patch, mock_open
from main import EncryptionManager, UserManager, PasswordDatabase, getTime

class TestEncryptionManager(unittest.TestCase):

    def setUp(self):
        self.key = "securepassword"
        self.encryption_manager = EncryptionManager(self.key)

    def test_encrypt_decrypt(self):
        plaintext = "Hello, World!"
        ciphertext = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted_text)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            EncryptionManager(12345)  # Invalid key type


class TestUserManager(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def test_initialization_creates_empty_file(self, mock_exists, mock_open):
        # Test that the JSON file is created if it doesn't exist
        manager = UserManager('test_users.json')
        mock_open.assert_called_with('test_users.json', 'w', encoding="utf-8")
        manager.saveUsers()  # Ensures users are saved correctly
        mock_open().write.assert_called_once_with('{}')

    @patch('builtins.open', new_callable=mock_open, read_data='{"testuser": {"masterPassword": "cGFzc3dvcmQ="}}')
    @patch('os.path.exists', return_value=True)
    def test_load_users(self, mock_exists, mock_open):
        # Test that users are loaded from the JSON file correctly
        manager = UserManager('test_users.json')
        self.assertEqual(manager.users, {"testuser": {"masterPassword": "cGFzc3dvcmQ="}})
    
    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_create_user(self, mock_exists, mock_open):
        # Test user creation
        manager = UserManager('test_users.json')
        result = manager.createUser('testuser', 'password')
        self.assertTrue(result)
        self.assertIn('testuser', manager.users)
        encoded_password = base64.b64encode(b'password').decode('utf-8')
        self.assertEqual(manager.users['testuser']['masterPassword'], encoded_password)

        # Test creating a user that already exists
        result = manager.createUser('testuser', 'newpassword')
        self.assertFalse(result)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_authenticate(self, mock_exists, mock_open):
        # Test user authentication
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        auth_result = manager.authenticate('testuser', 'password')
        self.assertTrue(auth_result)

        # Test failed authentication with wrong password
        auth_result = manager.authenticate('testuser', 'wrongpassword')
        self.assertFalse(auth_result)

        # Test authentication for non-existing user
        auth_result = manager.authenticate('nonexistentuser', 'password')
        self.assertFalse(auth_result)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_get_user_password(self, mock_exists, mock_open):
        # Test retrieving the user's password
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        retrieved_password = manager.getUserPassword('testuser')
        self.assertEqual(retrieved_password, b'password')

        # Test retrieving password for non-existing user
        retrieved_password = manager.getUserPassword('nonexistentuser')
        self.assertIsNone(retrieved_password)


class TestPasswordDatabase(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def test_initialization_creates_empty_file(self, mock_exists, mock_open):
        # Test that the JSON file is created if it doesn't exist
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        mock_open.assert_called_with('test_passwords.json', 'w', encoding="utf-8")
        manager.savePasswords()  # Ensures passwords are saved correctly
        mock_open().write.assert_called_once_with('{}')

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_load_passwords(self, mock_exists, mock_open):
        # Test that passwords are loaded from the JSON file correctly
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        self.assertIn('enc(service1)', manager.passwords)
        self.assertEqual(manager.passwords['enc(service1)']['username'], "enc(user1)")

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    @patch('your_module.getTime', return_value="2024-08-29 12:00:00")
    def test_add_password(self, mock_get_time, mock_exists, mock_open):
        # Test adding a new password
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        manager.addPassword('service1', 'user1', 'pass1', 'note1')

        self.assertIn('enc(service1)', manager.passwords)
        self.assertEqual(manager.passwords['enc(service1)']['username'], "enc(user1)")
        self.assertEqual(manager.passwords['enc(service1)']['password'], "enc(pass1)")
        self.assertEqual(manager.passwords['enc(service1)']['note'], "note1")
        self.assertEqual(manager.passwords['enc(service1)']['time'], "enc(2024-08-29 12:00:00)")

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_retrieve_password(self, mock_exists, mock_open):
        # Test retrieving an existing password
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        result = manager.retrievePassword('enc(service1)')

        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'user1')
        self.assertEqual(result['password'], 'pass1')
        self.assertEqual(result['note'], 'note1')
        self.assertEqual(result['time'], '2024-08-29 12:00:00')

        # Test retrieving a non-existing password
        result = manager.retrievePassword('enc(service2)')
        self.assertIsNone(result)

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_delete_password(self, mock_exists, mock_open):
        # Test deleting an existing password
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        # Delete and check
        delete_result = manager.deletePassword('enc(service1)')
        self.assertTrue(delete_result)
        self.assertNotIn('enc(service1)', manager.passwords)

        # Attempt to delete a non-existing password
        delete_result = manager.deletePassword('enc(service2)')
        self.assertFalse(delete_result)

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_is_instance(self, mock_exists, mock_open):
        # Test checking if a service exists
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        self.assertTrue(manager.isInstance('enc(service1)'))
        self.assertFalse(manager.isInstance('enc(service2)'))

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_get_services(self, mock_exists, mock_open):
        # Test retrieving all services in decrypted form
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        services = manager.getServices()
        self.assertIn('service1', services)
        self.assertNotIn('service2', services)

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_decrypt_service(self, mock_exists, mock_open):
        # Test decrypting a single service
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        decrypted_service = manager.decryptService('enc(service1)')
        self.assertEqual(decrypted_service, 'service1')

class TestUtils(unittest.TestCase):

    @patch('your_module.datetime')
    def test_get_time(self, mock_datetime):
        mock_datetime.now.return_value = datetime(2024, 8, 29, 12, 0, 0)
        time_string = getTime()
        self.assertEqual(time_string, "2024-08-29 12:00:00")

if __name__ == "__main__":
    unittest.main()

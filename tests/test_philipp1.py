import unittest
from unittest.mock import patch, mock_open, MagicMock
from main import EncryptionManager, UserManager, PasswordDatabase, getTime, checkPawndedApi
 
class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.password = "securepassword"
        self.encryption_manager = EncryptionManager(self.password)
 
    def test_encrypt_decrypt(self):
        plaintext = "This is a secret message."
        encrypted_text = self.encryption_manager.encrypt(plaintext)
        self.assertNotEqual(plaintext, encrypted_text)
        decrypted_text = self.encryption_manager.decrypt(encrypted_text)
        self.assertEqual(plaintext, decrypted_text)
 
    def test_invalid_key_type(self):
        with self.assertRaises(ValueError):
            EncryptionManager(12345)
 
class TestUserManager(unittest.TestCase):
    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def setUp(self, mock_exists, mock_open):
        self.user_manager = UserManager('test_users.json')
 
    @patch('main.EncryptionManager')
    def test_create_user(self, MockEncryptionManager):
        MockEncryptionManager.return_value.key = b'test_key'
        result = self.user_manager.createUser('testuser', 'testpassword')
        self.assertTrue(result)
        self.assertIn('testuser', self.user_manager.users)
 
    @patch('main.EncryptionManager')
    def test_authenticate_user(self, MockEncryptionManager):
        MockEncryptionManager.return_value.key = b'test_key'
        self.user_manager.createUser('testuser', 'testpassword')
        result = self.user_manager.authenticate('testuser', 'testpassword')
        self.assertTrue(result)
 
    def test_authenticate_user_invalid(self):
        result = self.user_manager.authenticate('nonexistentuser', 'testpassword')
        self.assertFalse(result)
 
class TestPasswordDatabase(unittest.TestCase):
    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def setUp(self, mock_exists, mock_open):
        self.encryption_manager = EncryptionManager("testkey")
        self.password_db = PasswordDatabase('test_passwords.json', self.encryption_manager)
 
    def test_add_retrieve_password(self):
        service = "example.com"
        username = "user"
        password = "password"
        note = "note"
        self.password_db.addPassword(service, username, password, note)
        retrieved = self.password_db.retrievePassword(service)
        self.assertEqual(retrieved['username'], username)
        self.assertEqual(retrieved['password'], password)
        self.assertEqual(retrieved['note'], note)
 
    def test_delete_password(self):
        service = "example.com"
        username = "user"
        password = "password"
        note = "note"
        self.password_db.addPassword(service, username, password, note)
        self.assertTrue(self.password_db.deletePassword(service))
        self.assertFalse(self.password_db.deletePassword("nonexistent"))
 
    def test_is_instance(self):
        service = "example.com"
        self.password_db.addPassword(service, "user", "password", "note")
        self.assertTrue(self.password_db.isInstance(service))
        self.assertFalse(self.password_db.isInstance("nonexistent"))
 
class TestUtils(unittest.TestCase):
    def test_get_time(self):
        time_string = getTime()
        self.assertRegex(time_string, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
 
    @patch('requests.get')
    def test_check_pawnded_api_safe(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = ''
        result = checkPawndedApi(MagicMock(), 'safe_password')
        self.assertFalse(result)
 
    @patch('requests.get')
    def test_check_pawnded_api_pawned(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = 'A003E7C14D1B4E4F9F432C39F3947E3D5E2:2'
        result = checkPawndedApi(MagicMock(), 'pawned_password')
        self.assertTrue(result)
 
    @patch('requests.get')
    def test_check_pawnded_api_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout
        result = checkPawndedApi(MagicMock(), 'timeout_password')
        self.assertFalse(result)
 
if __name__ == '__main__':
    unittest.main()
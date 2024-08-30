import unittest
import os
import tempfile
import base64
import sys
import hashlib
import requests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unittest.mock import patch, mock_open
from main import EncryptionManager, UserManager, PasswordDatabase, getTime, pwChecker, checkPawndedApi, customPassword, safePassword, changeInfo, changePassword, changeNote, passwordSelector, passwordGenerator, showServices, checkService, addPassword, retrievePassword, deletePassword

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

        manager = UserManager('test_users.json')
        mock_open.assert_called_with('test_users.json', 'w', encoding="utf-8")
        manager.saveUsers() 
        mock_open().write.assert_called_once_with('{}')

    @patch('builtins.open', new_callable=mock_open, read_data='{"testuser": {"masterPassword": "cGFzc3dvcmQ="}}')
    @patch('os.path.exists', return_value=True)
    def test_load_users(self, mock_exists, mock_open):
        
        manager = UserManager('test_users.json')
        self.assertEqual(manager.users, {"testuser": {"masterPassword": "cGFzc3dvcmQ="}})
    
    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_create_user(self, mock_exists, mock_open):
       
        manager = UserManager('test_users.json')
        result = manager.createUser('testuser', 'password')
        self.assertTrue(result)
        self.assertIn('testuser', manager.users)
        encoded_password = base64.b64encode(b'password').decode('utf-8')
        self.assertEqual(manager.users['testuser']['masterPassword'], encoded_password)

        
        result = manager.createUser('testuser', 'newpassword')
        self.assertFalse(result)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_authenticate(self, mock_exists, mock_open):
        
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        auth_result = manager.authenticate('testuser', 'password')
        self.assertTrue(auth_result)

        
        auth_result = manager.authenticate('testuser', 'wrongpassword')
        self.assertFalse(auth_result)

        
        auth_result = manager.authenticate('nonexistentuser', 'password')
        self.assertFalse(auth_result)

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    def test_get_user_password(self, mock_exists, mock_open):
      
        manager = UserManager('test_users.json')
        manager.createUser('testuser', 'password')
        retrieved_password = manager.getUserPassword('testuser')
        self.assertEqual(retrieved_password, b'password')

       
        retrieved_password = manager.getUserPassword('nonexistentuser')
        self.assertIsNone(retrieved_password)


class TestPasswordDatabase(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def test_initialization_creates_empty_file(self, mock_exists, mock_open):
        
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        mock_open.assert_called_with('test_passwords.json', 'w', encoding="utf-8")
        manager.savePasswords() 
        mock_open().write.assert_called_once_with('{}')

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_load_passwords(self, mock_exists, mock_open):
       
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        self.assertIn('enc(service1)', manager.passwords)
        self.assertEqual(manager.passwords['enc(service1)']['username'], "enc(user1)")

    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=True)
    @patch('your_module.getTime', return_value="2024-08-29 12:00:00")
    def test_add_password(self, mock_get_time, mock_exists, mock_open):
       
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
       
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)
        result = manager.retrievePassword('enc(service1)')

        self.assertIsNotNone(result)
        self.assertEqual(result['username'], 'user1')
        self.assertEqual(result['password'], 'pass1')
        self.assertEqual(result['note'], 'note1')
        self.assertEqual(result['time'], '2024-08-29 12:00:00')

        result = manager.retrievePassword('enc(service2)')
        self.assertIsNone(result)

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_delete_password(self, mock_exists, mock_open):
        
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        delete_result = manager.deletePassword('enc(service1)')
        self.assertTrue(delete_result)
        self.assertNotIn('enc(service1)', manager.passwords)

        delete_result = manager.deletePassword('enc(service2)')
        self.assertFalse(delete_result)

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_is_instance(self, mock_exists, mock_open):

        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        self.assertTrue(manager.isInstance('enc(service1)'))
        self.assertFalse(manager.isInstance('enc(service2)'))

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_get_services(self, mock_exists, mock_open):
        
        encryption_manager = EncryptionManager("key")
        manager = PasswordDatabase('test_passwords.json', encryption_manager)

        services = manager.getServices()
        self.assertIn('service1', services)
        self.assertNotIn('service2', services)

    @patch('builtins.open', new_callable=mock_open, read_data='{"enc(service1)": {"username": "enc(user1)", "password": "enc(pass1)", "note": "note1", "time": "enc(2024-08-29 12:00:00)"}}')
    @patch('os.path.exists', return_value=True)
    def test_decrypt_service(self, mock_exists, mock_open):
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

class testPwChecker(unittest.TestCase):

    def test_safe_password(self, mock_curses, mock_checkPawndedApi):
        mock_stdscr = Mock()

        mock_checkPawndedApi.return_value = False

        result = pwChecker(mock_stdscr, "SafePassword123!")

        self.assertTrue(result)

        mock_stdscr.addstr.assert_called_with(3, 0, "Your password is safe and has been added successfully!")

   
    def test_short_password(self, mock_curses, mock_checkPawndedApi):
        mock_stdscr = Mock()
        mock_checkPawndedApi.return_value = False

        result = pwChecker(mock_stdscr, "Short1!")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(2, 0, "A safe password should be between 8 and 20 Characters!", curses.color_pair(2))

   
    def test_missing_uppercase(self, mock_curses, mock_checkPawndedApi):
        mock_stdscr = Mock()
        mock_checkPawndedApi.return_value = False

        result = pwChecker(mock_stdscr, "lowercase1!")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(3, 0, "The password should contain at least one uppercase letter!", curses.color_pair(2))

    
    def test_missing_number(self, mock_curses, mock_checkPawndedApi):
        mock_stdscr = Mock()
        mock_checkPawndedApi.return_value = False

        result = pwChecker(mock_stdscr, "Password!")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(5, 0, "The password should contain at least one number!", curses.color_pair(2))

    
    def test_missing_special_char(self, mock_curses, mock_checkPawndedApi):
        mock_stdscr = Mock()
        mock_checkPawndedApi.return_value = False

        result = pwChecker(mock_stdscr, "Password123")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(6, 0, "The password should contain at least one special letter!", curses.color_pair(2))

    
    def test_password_leaked(self, mock_curses, mock_checkPawndedApi):
        mock_stdscr = Mock()

        mock_checkPawndedApi.return_value = True

        result = pwChecker(mock_stdscr, "SafePassword123!")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(7, 0, "Your password has been leaked!", curses.color_pair(2))

class TestCheckPawndedApi(unittest.TestCase):

    @patch('main.requests.get')
    def test_password_pawned(self, mock_get):
        mock_stdscr = Mock()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "01234ABCDE12345:10"
        mock_get.return_value = mock_response

        result = checkPawndedApi(mock_stdscr, "password123")
        
        self.assertTrue(result)

    @patch('main.requests.get')
    def test_password_not_pawned(self, mock_get):
        mock_stdscr = Mock()

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "01234ABCDE12346:5"
        mock_get.return_value = mock_response

        result = checkPawndedApi(mock_stdscr, "differentpassword")
        
        self.assertFalse(result)

    @patch('main.requests.get')
    def test_api_timeout(self, mock_get):
        mock_stdscr = Mock()

        mock_get.side_effect = requests.exceptions.Timeout

        result = checkPawndedApi(mock_stdscr, "password123")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(8, 0, "The request to 'have I been pawned API' timed out.")

    @patch('main.requests.get')
    def test_api_request_exception(self, mock_get):
        mock_stdscr = Mock()

        mock_get.side_effect = requests.exceptions.RequestException

        result = checkPawndedApi(mock_stdscr, "password123")
        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(8, 0, "Error connecting to 'have I been pawned API'")

    @patch('main.requests.get')
    def test_api_404(self, mock_get):
        mock_stdscr = Mock()
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = checkPawndedApi(mock_stdscr, "password123")

        self.assertFalse(result)

    @patch('main.requests.get')
    def test_api_other_status_code(self, mock_get):
        mock_stdscr = Mock()

        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = checkPawndedApi(mock_stdscr, "password123")

        self.assertFalse(result)
        mock_stdscr.addstr.assert_called_with(8, 0, "Error accessing data from 'have I been pawned' (status code: 500)")

class TestCustomPassword(unittest.TestCase):

    @patch('main.pwChecker')
    @patch('main.safePassword')
    def test_custom_password_safe(self, mock_safePassword, mock_pwChecker):
        mock_stdscr = Mock()

        mock_stdscr.getstr.return_value = b'SafePassword123!'
        mock_pwChecker.return_value = True

        result = customPassword(mock_stdscr)

        self.assertEqual(result, 'SafePassword123!')
        mock_pwChecker.assert_called_once_with(mock_stdscr, 'SafePassword123!')
        mock_stdscr.addstr.assert_any_call(0, 0, "Enter you´r desired password: ")

    @patch('main.pwChecker')
    @patch('main.safePassword')
    def test_custom_password_not_safe_edit(self, mock_safePassword, mock_pwChecker):
        mock_stdscr = Mock()

        mock_stdscr.getstr.return_value = b'WeakPassword'
        mock_pwChecker.return_value = False
        mock_safePassword.return_value = 'SafePassword123!'

        mock_stdscr.getch.side_effect = [
            curses.KEY_ENTER,  # User chooses to edit the password
        ]

        result = customPassword(mock_stdscr)

        self.assertEqual(result, 'SafePassword123!')
        mock_pwChecker.assert_called_once_with(mock_stdscr, 'WeakPassword')
        mock_safePassword.assert_called_once_with(mock_stdscr, 'WeakPassword')

    @patch('main.pwChecker')
    @patch('main.safePassword')
    def test_custom_password_not_safe_do_not_edit(self, mock_safePassword, mock_pwChecker):
        mock_stdscr = Mock()

        mock_stdscr.getstr.return_value = b'WeakPassword'
        mock_pwChecker.return_value = False

        mock_stdscr.getch.side_effect = [
            curses.KEY_DOWN,  # Navigate to 'No'
            curses.KEY_ENTER,  # Select 'No'
        ]

        result = customPassword(mock_stdscr)

        self.assertEqual(result, 'WeakPassword')
        mock_pwChecker.assert_called_once_with(mock_stdscr, 'WeakPassword')
        mock_safePassword.assert_not_called()

if __name__ == "__main__":
    unittest.main()

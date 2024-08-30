import unittest
from unittest.mock import patch, mock_open, MagicMock
import requests
import curses
from main import (
    EncryptionManager,
    UserManager,
    PasswordDatabase,
    getTime,
    checkPawndedApi,
    customPassword,
    safePassword,
    pwChecker,
    addNotes,
    passwordSelector,
    passwordGenerator,
    changeInfo,
    changePassword,
    changeUsername,
    changeNote,
    startScreen,
    loginScreen,
    createUserScreen,
    mainMenu,
    checkService,
    passwordMenu,
    addPassword,
    retrievePassword,
    deletePassword,
    showServices,
    main
)

class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.password = "securepassword"
        self.encryption_manager = EncryptionManager(self.password)

    def test_initialization_with_string(self):
        manager = EncryptionManager("testpassword")
        self.assertIsInstance(manager.key, bytes)
    
    def test_initialization_with_bytes(self):
        manager = EncryptionManager(b'\x00' * 32)
        self.assertIsInstance(manager.key, bytes)
    
    def test_initialization_invalid_type(self):
        with self.assertRaises(ValueError):
            EncryptionManager(12345)

    def test_encrypt(self):
        plaintext = "This is a secret message."
        encrypted_text = self.encryption_manager.encrypt(plaintext)
        self.assertNotEqual(plaintext, encrypted_text)
        self.assertIsInstance(encrypted_text, str)

    def test_decrypt(self):
        plaintext = "This is a secret message."
        encrypted_text = self.encryption_manager.encrypt(plaintext)
        decrypted_text = self.encryption_manager.decrypt(encrypted_text)
        self.assertEqual(plaintext, decrypted_text)


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

    def test_create_user_existing(self):
        self.user_manager.users['testuser'] = {'masterPassword': 'somehash'}
        result = self.user_manager.createUser('testuser', 'testpassword')
        self.assertFalse(result)

    @patch('main.EncryptionManager')
    def test_authenticate_user(self, MockEncryptionManager):
        MockEncryptionManager.return_value.key = b'test_key'
        self.user_manager.createUser('testuser', 'testpassword')
        result = self.user_manager.authenticate('testuser', 'testpassword')
        self.assertTrue(result)

    def test_authenticate_user_invalid_password(self):
        self.user_manager.users['testuser'] = {'masterPassword': base64.b64encode(b'invalid').decode('utf-8')}
        result = self.user_manager.authenticate('testuser', 'wrongpassword')
        self.assertFalse(result)

    def test_authenticate_user_nonexistent(self):
        result = self.user_manager.authenticate('nonexistentuser', 'testpassword')
        self.assertFalse(result)

    def test_get_user_password(self):
        self.user_manager.users['testuser'] = {'masterPassword': base64.b64encode(b'somehash').decode('utf-8')}
        master_password = self.user_manager.getUserPassword('testuser')
        self.assertEqual(master_password, b'somehash')

    def test_get_user_password_nonexistent(self):
        master_password = self.user_manager.getUserPassword('nonexistentuser')
        self.assertIsNone(master_password)


class TestPasswordDatabase(unittest.TestCase):
    @patch('builtins.open', new_callable=mock_open, read_data='{}')
    @patch('os.path.exists', return_value=False)
    def setUp(self, mock_exists, mock_open):
        self.encryption_manager = EncryptionManager("testkey")
        self.password_db = PasswordDatabase('test_passwords.json', self.encryption_manager)

    def test_add_password(self):
        service = "example.com"
        username = "user"
        password = "password"
        note = "note"
        self.password_db.addPassword(service, username, password, note)
        self.assertIn(self.encryption_manager.encrypt(service), self.password_db.passwords)

    def test_retrieve_password(self):
        service = "example.com"
        username = "user"
        password = "password"
        note = "note"
        self.password_db.addPassword(service, username, password, note)
        retrieved = self.password_db.retrievePassword(self.encryption_manager.encrypt(service))
        self.assertEqual(retrieved['username'], username)
        self.assertEqual(retrieved['password'], password)
        self.assertEqual(retrieved['note'], note)

    def test_retrieve_password_nonexistent(self):
        retrieved = self.password_db.retrievePassword("nonexistent_service")
        self.assertIsNone(retrieved)

    def test_delete_password(self):
        service = "example.com"
        self.password_db.addPassword(service, "user", "password", "note")
        self.assertTrue(self.password_db.deletePassword(self.encryption_manager.encrypt(service)))
        self.assertFalse(self.password_db.deletePassword("nonexistent_service"))

    def test_is_instance(self):
        service = "example.com"
        self.password_db.addPassword(service, "user", "password", "note")
        self.assertTrue(self.password_db.isInstance(self.encryption_manager.encrypt(service)))
        self.assertFalse(self.password_db.isInstance("nonexistent_service"))

    def test_get_services(self):
        service = "example.com"
        self.password_db.addPassword(service, "user", "password", "note")
        services = self.password_db.getServices()
        self.assertIn(service, services)

    def test_decrypt_service(self):
        service = "example.com"
        encrypted_service = self.encryption_manager.encrypt(service)
        decrypted_service = self.password_db.decryptService(encrypted_service)
        self.assertEqual(service, decrypted_service)


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

    @patch('curses.getch', return_value=10)  # Simulate pressing the Enter key
    @patch('curses.echo')
    @patch('curses.start_color')
    @patch('curses.init_pair')
    @patch('curses.wrapper')
    def test_curses_functions(self, mock_wrapper, mock_init_pair, mock_start_color, mock_echo, mock_getch):
        stdscr_mock = MagicMock()
        password = customPassword(stdscr_mock)
        self.assertIsInstance(password, str)
        
        safe_password = safePassword(stdscr_mock, "password")
        self.assertIsInstance(safe_password, str)
        
        pw_safe = pwChecker(stdscr_mock, "Password123!")
        self.assertTrue(pw_safe)
        
        note = addNotes(stdscr_mock)
        self.assertIsInstance(note, str)

    @patch('curses.getstr', return_value=b'20')
    @patch('curses.getch', return_value=10)  # Simulate pressing the Enter key
    @patch('curses.echo')
    def test_password_selector(self, mock_echo, mock_getch, mock_getstr):
        stdscr_mock = MagicMock()
        password = passwordSelector(stdscr_mock)
        self.assertIsInstance(password, str)


if __name__ == '__main__':
    unittest.main()

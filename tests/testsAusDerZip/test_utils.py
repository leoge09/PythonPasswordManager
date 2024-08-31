import unittest
import sys
import os
from unittest.mock import patch, Mock
import curses

# Füge das Verzeichnis eine Ebene höher zum Python-Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import getTime, customPassword, safePassword

class TestUtils(unittest.TestCase):

    @patch('main.datetime')
    def test_get_time_daylight_savings(self, mock_datetime):
        mock_datetime.now.return_value = datetime.datetime(2024, 10, 26, 23, 0, 0)
        time_string = getTime()
        self.assertEqual(time_string, "2024-10-26 23:00:00")

    @patch('main.curses.initscr')
    @patch('main.curses.start_color')
    @patch('main.curses.init_pair')
    @patch('main.curses.newwin')
    def test_custom_password_empty_input(self, mock_newwin, mock_init_pair, mock_start_color, mock_initscr):
        mock_stdscr = Mock()
        mock_newwin.return_value = mock_stdscr
        mock_stdscr.getstr.return_value = b''
        with self.assertRaises(ValueError):
            customPassword(mock_stdscr)

    def test_safe_password_empty_input(self):
        with self.assertRaises(ValueError):
            safePassword('')

    def test_safe_password_weak_password(self):
        result = safePassword('weak')
        self.assertIsNotNone(result)
        self.assertNotEqual(result, 'weak')

if __name__ == "__main__":
    unittest.main()

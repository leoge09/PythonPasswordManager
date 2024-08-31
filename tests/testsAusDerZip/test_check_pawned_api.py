import unittest
import sys
import os
from unittest.mock import patch, Mock

# Füge das Verzeichnis eine Ebene höher zum Python-Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import checkPawndedApi

class TestCheckPawndedApi(unittest.TestCase):

    @patch('main.requests.get')
    def test_password_pawned(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "01234ABCDE12345:10"
        mock_get.return_value = mock_response

        result = checkPawndedApi(None, "password123")
        self.assertTrue(result)

    @patch('main.requests.get')
    def test_password_not_pawned(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "01234ABCDE12346:0"
        mock_get.return_value = mock_response

        result = checkPawndedApi(None, "differentpassword")
        self.assertFalse(result)

    @patch('main.requests.get')
    def test_api_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout

        result = checkPawndedApi(None, "password123")
        self.assertFalse(result)

    @patch('main.requests.get')
    def test_api_request_exception(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException

        result = checkPawndedApi(None, "password123")
        self.assertFalse(result)

    @patch('main.requests.get')
    def test_api_404(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = checkPawndedApi(None, "password123")
        self.assertFalse(result)

    @patch('main.requests.get')
    def test_api_other_status_code(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = checkPawndedApi(None, "password123")
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()

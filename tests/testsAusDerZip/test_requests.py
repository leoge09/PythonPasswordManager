import unittest
import sys
import os
from unittest.mock import patch, Mock
import requests
from requests.exceptions import Timeout, RequestException

# Füge das Verzeichnis eine Ebene höher zum Python-Pfad hinzu
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestRequests(unittest.TestCase):

    @patch('requests.get')
    def test_get_request_timeout(self, mock_get):
        mock_get.side_effect = Timeout
        with self.assertRaises(Timeout):
            requests.get('http://example.com', timeout=0.001)

    @patch('requests.get')
    def test_get_request_http_error(self, mock_get):
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError
        mock_get.return_value = mock_response
        with self.assertRaises(requests.exceptions.HTTPError):
            response = requests.get('http://example.com')
            response.raise_for_status()

    @patch('requests.get')
    def test_get_request_request_exception(self, mock_get):
        mock_get.side_effect = RequestException
        with self.assertRaises(RequestException):
            requests.get('http://example.com')

if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch, Mock
import urllib3
from urllib3.exceptions import HTTPError, TimeoutError

class TestUrllib3(unittest.TestCase):

    @patch('urllib3.PoolManager.request')
    def test_pool_manager_request_timeout(self, mock_request):
        mock_request.side_effect = TimeoutError
        with self.assertRaises(TimeoutError):
            http = urllib3.PoolManager()
            http.request('GET', 'http://example.com', timeout=0.001)

    @patch('urllib3.PoolManager.request')
    def test_pool_manager_http_error(self, mock_request):
        mock_response = Mock()
        mock_response.status = 404
        mock_request.return_value = mock_response
        http = urllib3.PoolManager()
        response = http.request('GET', 'http://example.com')
        self.assertEqual(response.status, 404)

if __name__ == "__main__":
    unittest.main()

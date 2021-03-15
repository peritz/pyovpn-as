"""Tests functions in the pyovpn_as.client module
"""
import unittest
import unittest.mock

from pyovpn_as import client
from pyovpn_as.api import exceptions


class TestValidateEndpoint(unittest.TestCase):
    """TestCase for the validate_endpoint function
    """

    def test_valid_endpoint_returns_true(self):
        endpoint = 'https://ip-address/RPC2/'
        self.assertTrue(client.validate_endpoint(endpoint))

    def test_http_scheme_returns_false(self):
        endpoint = 'http://ip-address/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_ftp_scheme_returns_false(self):
        endpoint = 'ftp://ip-address/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_username_in_netloc_returns_false(self):
        endpoint = 'https://username@ip-address/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_passsword_in_netloc_returns_false(self):
        endpoint = 'https://:password@ip-address/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_only_userpass_in_netloc_returns_false(self):
        endpoint = 'https://username:password@/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_blank_netloc_returns_false(self):
        endpoint = 'https:///RPC2/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_get_query_returns_false(self):
        endpoint = 'https://ip-address/?param=val'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_parameters_returns_false(self):
        endpoint = 'https://ip-address/RPC2;param=val'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_fragments_returns_false(self):
        endpoint = 'https://ip-address/#fragment'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_valid_port_number_returns_true(self):
        endpoint = 'https://ip-address:443/'
        self.assertTrue(client.validate_endpoint(endpoint))

    def test_high_port_number_returns_false(self):
        endpoint = 'https://ip-address:65536/'
        self.assertFalse(client.validate_endpoint(endpoint))

    def test_negative_port_number_returns_false(self):
        endpoint = 'https://ip-address:-1/'
        self.assertFalse(client.validate_endpoint(endpoint))


@unittest.mock.patch('pyovpn_as.client.validate_endpoint', return_value=True)
class TestValidateClientArgs(unittest.TestCase):
    """TestCase for the validate_client_args function
    """

    def test_valid_args_returns_true(self, *args):
        self.assertTrue(
            client.validate_client_args(
                'https://endpoint/',
                'username',
                'password'
            )
        )

    def test_none_endpoint_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Endpoint URL has not been set, cannot create client'
        ):
            client.validate_client_args(
                None,
                'username',
                'password'
            )

    def test_non_str_endpoint_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Endpoint URL is not a string, cannot create client'
        ):
            client.validate_client_args(
                [],
                'username',
                'password'
            )

    def test_none_username_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Username is not set, cannot create client'
        ):
            client.validate_client_args(
                'https://endpoint/',
                None,
                'password'
            )

    def test_non_str_username_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Username is not a string, cannot create client'
        ):
            client.validate_client_args(
                'https://endpoint/',
                [],
                'password'
            )

    def test_colon_in_username_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Username contains ":" character \(illegal in basic auth\), '
            'cannot create client'
        ):
            client.validate_client_args(
                'https://endpoint/',
                'user:name',
                'password'
            )

    def test_none_password_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Password is not set, cannot create client'
        ):
            client.validate_client_args(
                'https://endpoint/',
                'username',
                None
            )

    def test_non_str_password_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Password is not a string, cannot create client'
        ):
            client.validate_client_args(
                'https://endpoint/',
                'username',
                []
            )

    def test_colon_in_password_raises_error(self, *args):
        with self.assertRaisesRegex(
            exceptions.ApiClientConfigurationError,
            'Password contains ":" character \(illegal in basic auth\), '
            'cannot create client'
        ):
            client.validate_client_args(
                'https://endpoint/',
                'username',
                'pass:word'
            )

if __name__ == '__main__':
    unittest.main()
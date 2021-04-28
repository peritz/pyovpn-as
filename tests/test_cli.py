"""Tests the classes in pyovpn_as.api.cli
"""
import unittest

from pyovpn_as.api import cli
from pyovpn_as.api.exceptions import ApiClientPasswordComplexityError

class TestIsPasswordComplex(unittest.TestCase):
    """This TestCase tests the is_password_complex static method of the
       AccessServerClient class
    """

    def test_compliant_password_returns_true(self):
        password = 'Th1sIs4C0mpliantPassw0rd%'
        try:
            self.assertTrue(
                cli.RemoteSacli.is_password_complex(password)
            )
        except Exception as err:
            self.fail(f'Password complexity check failed: {err}')

    def test_short_password_raises_error(self):
        password = '$T2a'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_7_char_password_raises_error(self):
        password = '$T2a123'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_8_char_password_returns_true(self):
        password = '$T2a1234'
        try:
            self.assertTrue(
                cli.RemoteSacli.is_password_complex(password)
            )
        except Exception as err:
            self.fail(f'Password complexity check failed: {err}')

    def test_very_long_password_returns_true(self):
        password = f'$T2a{"a" * 1000000}'
        try:
            self.assertTrue(
                cli.RemoteSacli.is_password_complex(password)
            )
        except Exception as err:
            self.fail(f'Password complexity check failed: {err}')

    def test_none_password_raises_error(self):
        password = None
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_non_str_password_raises_TypeError(self):
        password = []
        with self.assertRaises(TypeError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_no_digit_raises_error(self):
        password = 'abcdE$Gh'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_no_lowercase_raises_error(self):
        password = 'ABCDE$G1'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_no_uppercase_raises_error(self):
        password = 'abcde$g1'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_with_each_symbol_returns_true(self):
        password = 'Th1sIs4C0mpliantPassw0rd%'
        for sym in "!@#$%&'()*+,-/[\\]^_`{|}~<>.":
            password = password[:-1] + sym
            try:
                self.assertTrue(
                    cli.RemoteSacli.is_password_complex(password)
                )
            except ApiClientPasswordComplexityError as err:
                self.fail(
                    f'Password complexity check failed with symbol {sym}: {err}'
                )

    def test_password_with_disallowed_symbols_raises_error(self):
        password = 'abcde:g1'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_with_control_characters_raises_error(self):
        password = 'abcde\x08g1'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_with_whitespace_raises_error(self):
        password = 'abcde\ng1'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)

    def test_password_with_non_ascii_raises_error(self):
        password = 'abcde\u0394g1'
        with self.assertRaises(ApiClientPasswordComplexityError):
            cli.RemoteSacli.is_password_complex(password)


if __name__ == '__main__':
    unittest.main()
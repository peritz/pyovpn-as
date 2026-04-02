"""Provides a HTTP client for the REST API endpoint"""

from logging import getLogger
from datetime import datetime, timezone
import urllib.parse

from requests import Response, Session
from .exceptions import ApiClientPasswordComplexityError

logger = getLogger(__name__)

class RestApiClient:
    """Client to handle direct HTTP REST API calls

    Attributes:

    Args:
        endpoint (str): The full URL of the REST API endpoint without trailing slash
            (usually https://<ip/domain-of-access-server>/api)
        username (str): Username of an admin user on the remote server
        password (str): Password for the above user
        debug (bool): Can be set which will provide debug output. Defaults
            to False
        allow_untrusted (bool): Trusts untrusted SSL certificates coming
            from the target server. Defaults to False
    """

    AUTH_HEADER = "X-OpenVPN-As-AuthToken"

    def __init__(
        self,
        endpoint: str,
        username: str,
        password: str,
        debug: bool = False,
        allow_untrusted: bool = False,
    ):
        self._endpoint = endpoint

        self._session = Session()
        self._session.verify = not allow_untrusted

        auth = self._auth_by_userpass(username, password)
        self._session.headers[self.AUTH_HEADER] = auth["auth_token"]
        self._auth_expires = datetime.fromisoformat(auth["expires_after"])

    def _auth_by_userpass(self, username: str, password: str) -> dict[str]:
        """Authenticate with the API using a username and password

        Does not raise specific errors per auth issue.

        Args:
            username (str): User name of the admin user on the remote server
            password (str): Password for the above user

        Returns:
            dict[str]: loginResponse as documented at https://openvpn.net/as-docs/rest-api/index-en.html#loginresponse
        """
        res = self._session.post(
            f"{self._endpoint}/auth/login/userpassword",
            json={"username": username, "password": password, "request_admin": True},
        )
        if res.status_code != 200:
            logger.error(f"Authentication failed with status code {res.status_code} and response: {res.text}")
        res.raise_for_status()
        return res.json()

    def _auth_renew_token(self):
        """Renews the authentication token and updates the session headers"""
        res = self._session.post(f"{self._endpoint}/auth/token/renew")
        res.raise_for_status()
        auth = res.json()
        self._session.headers[self.AUTH_HEADER] = auth["auth_token"]
        self._auth_expires = datetime.fromisoformat(auth["expires_after"])

    def request(self, method: str, path: str, json: dict = None) -> dict:
        """Checks that auth is valid, renews a token if necessary, and then sends a request

        Args:
            method (str): HTTP method to use
            path (str): API path to send the request to
            json (dict): JSON data to send in the request if necessary

        Returns:
            dict: JSON response
        """
        if self._auth_expires >= datetime.now(timezone.utc):
            self._auth_renew_token()
        res = self._session.request(method, f"{self._endpoint}{path}", json=json)
        res.raise_for_status()
        return res.json()

    def request_text(self, method: str, path: str, json: dict = None) -> str:
        """Checks that auth is valid, renews a token if necessary, and then sends a request
        returning the text response

        Args:
            method (str): HTTP method to use
            path (str): API path to send the request to
            json (dict): JSON data to send in the request if necessary

        Returns:
            str: Text response
        """
        if self._auth_expires >= datetime.now(timezone.utc):
            self._auth_renew_token()
        res = self._session.request(method, f"{self._endpoint}{path}", json=json)
        res.raise_for_status()
        return res.text

    def get(self, path: str) -> dict:
        """Performs a HTTP GET request

        Args:
            path (str): API path to send the request to

        Returns:
            dict: JSON response
        """
        return self.request("GET", path)

    def post(self, path: str, json: dict = None) -> dict:
        """Performs a HTTP POST request

        Args:
            path (str): API path to send the request to
            json (dict): JSON data to send in the request if necessary

        Returns:
            dict: JSON response
        """
        return self.request("POST", path, json=json)

    @staticmethod
    def is_password_complex(new_pass: str) -> bool:
        """Validate that a password is suitably complex for OpenVPN AS

        An OpenVPN Access Server password must be at least 8 characters long and
        contain a digit, an uppercase letter, a lowercase letter and a symbol
        from !@#$%&'()*+,-/[\\]^_`{|}~<>. (full stop included, also note
        absence of colon and double quotation marks).

        Args:
            new_pass (str): Password to check validate

        Raises:
            ApiClientPasswordComplexityError: Password is not complex enough

        Returns:
            bool: True if the password is suitably complex
        """
        complexity_err = ApiClientPasswordComplexityError(
            "New Password must be at least 8 characters. Password must "
            "also contain a digit, an Uppercase letter, and a symbol from "
            "!@#$%&'()*+,-/[\\]^_`{|}~<>."
        )
        # None
        if new_pass is None:
            raise complexity_err
        # Catch someone not passing string
        if not isinstance(new_pass, str):
            raise TypeError(
                'is_password_complex expected new_pass to be str, got '
                f'{type(new_pass)}'
            )
        # Length
        if len(new_pass) < 8:
            raise complexity_err
        # Uppercase lowercase
        if new_pass.upper() == new_pass or new_pass.lower() == new_pass:
            raise complexity_err
        # Digit
        contains_digit = False
        for i in '0123456789':
            if i in new_pass:
                contains_digit = True
                break
        # Symbol
        contains_symbol = False
        for s in "!@#$%&'()*+,-/[\\]^_`{|}~<>.":
            if s in new_pass:
                contains_symbol = True
                break
        if not contains_symbol or not contains_digit:
            raise complexity_err
        
        return True
            


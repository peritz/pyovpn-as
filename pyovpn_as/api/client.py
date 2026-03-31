"""Provides a HTTP client for the REST API endpoint"""

from datetime import datetime

from requests import Response, Session


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
        if ":" in password:
            raise ValueError('Password cannot contain ":"')
        elif ":" in username:
            raise ValueError('Username cannot contain ":"')

        self._endpoint = endpoint

        self._session = Session()
        self._session.verify = not allow_untrusted

        safe_username = urllib.parse.quote(username, safe="")
        safe_password = urllib.parse.quote(password, safe="")
        auth = self._auth_by_userpass(safe_username, safe_password)
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
            json={"username": username, "password": password},
        )
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
        if self._auth_expires >= datetime.now():
            self._auth_renew_token()
        res = self._session.request(method, f"{self._endpoint}/{path}", json=json)
        res.raise_for_status()
        return res.json()

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
        return self.request("POST", path)

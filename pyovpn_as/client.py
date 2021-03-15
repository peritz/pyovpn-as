"""Provides functions to fetch AccessServerClient from multiple different
   credential sources, e.g. environment variables or a file
"""
import urllib.parse


def validate_endpoint(url: str) -> bool:
    """Validates that a given URL is a (syntactically) valid endpoint URI for
       an AccessServer XML-RPC interface

    A valid endpoint would be a URL with no username and password (as in this
    module we construct these in the header rather than the URL), a https
    scheme, and no parameters or fragments. Very simply,
    https://hostname[:port]/path/

    Args:
        url (str): URL to validate

    Returns:
        bool: True if valid, False if not
    """
    parsed = urllib.parse.urlparse(url)
    print(parsed)
    # Verify https
    if parsed.scheme != 'https':
        return False
    # Verify no username or password
    elif parsed.username is not None or parsed.password is not None:
        return False
    # Verify hostname exists
    elif parsed.hostname is None or len(parsed.hostname) == 0:
        return False
    # Verify no params or fragments
    elif parsed.params != '' \
        or parsed.fragment != '' \
        or parsed.query != '':
        return False
    # Verify port is valid
    try:
        parsed.port
    except ValueError:
        return False
    else:
        return True

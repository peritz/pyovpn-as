"""A module that provides some useful functions and decorators
"""
import functools
import logging
import secrets
import string

from pyovpn_as.api.cli import AccessServerClient

from . import _exceptions

logger = logging.getLogger(__name__)

def debug_log_call(f):
    """Logs the function called and the arguments passed at the debug level
    """
    functools.wraps(f)
    def wrapper(*args, **kwargs):
        logger.debug(
            f'{f.__name__}() called with *args={repr(args)}, '
            f'**kwargs={repr(kwargs)}'
        )
        return f(*args, **kwargs)
    return wrapper


def generate_random_password(length: int=16, retries: int=10) -> str:
    """Generates a pseudo-random password consisting of lowercase, uppercase,
       digits and symbols

    Args:
        length (int, optional): Length of password to generate. Defaults to 16.
        retries (int, optional): Number of passwords to try before giving up on
            finding complex password. Defaults to 10.

    Raises:
        ValueError: The length provided is too short, it must be 8 or greater.
        PasswordGenerationComplexityTimeout: We could not create a suitably
            complex password after the given numebr of tries

    Returns:
        str: A suitably complex password of the given length
    """
    if length < 8:
        raise ValueError(
            'Length of password must be greater than or equal to 8'
        )
    
    complex = False
    tried = 0
    characters = list(
        string.ascii_letters
        + string.digits
        + "!@#$%&'()*+,-/[\\]^_`{|}~<>."
    )
    while not complex:
        if tried >= retries:
            raise _exceptions.PasswordGenerationComplexityTimeout(
                f'Could not find a suitably complex password in {retries}'
                ' attempts'
            )
        password = ''.join([secrets.choice(characters) for _ in range(length)])
        try:
            complex = AccessServerClient.is_password_complex(password)
        except:
            continue
        tried += 1
    return password
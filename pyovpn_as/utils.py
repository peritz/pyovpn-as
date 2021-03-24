"""A module that provides some useful functions and decorators
"""
import functools
import logging

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
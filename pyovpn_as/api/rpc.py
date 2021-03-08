"""Contains the RPC client that will handle low-level XML-RPC API calls to the
OpenVPN Access Server.
"""
import builtins
import json
import pathlib
from typing import Any


class _SupportedMethod:
    """Code for this is similar to the same code as in xmlrpc.client for
    _Method class.

    https://github.com/python/cpython/blob/374ee449331bc95d18c37f5032aaea1448462e58/Lib/xmlrpc/client.py#L1107-L1116

    Attributes:
        __send (callable): Callable that we are invoking when we call this
            method
        __name (str): Name of the method we are calling
        METHODS (dict): Definition of methods and their parameters (defined
            at the bottom of the file when read from config file)
        PARAM_KEY (str): Key used to get parameters from method definitions
        TYPE_KEY (str): Key used to get param type from param definition
        DEFAULT_KEY (str): Key used to get default value from param definition
        REQUIRED_KEY (str): Key used to get whether a param is required or not
        NULL_KEY (str): Key used to get whether a param can be null or not
        NAME_KEY (str): Key used to get (our) name of the parameter
    
    Args:
        send (callable): Callable that will be __send
        name (str): Name of method which will be __name

    Raises:
        AttributeError: Unsupported method name passed
    """
    METHODS: dict

    PARAM_KEY = 'params'
    TYPE_KEY = 'type'
    DEFAULT_KEY = 'default'
    REQUIRED_KEY = 'required'
    NULL_KEY = 'null'
    NAME_KEY = 'name'

    def __init__(self, send, name):
        self.__send = send
        self.__name = name
        method = self.METHODS.get(self.__name)
        # Raise attribute error if unsupported method
        if method == None:
            raise AttributeError("'RpcClient' object has no "
                f"attribute '{self.__name.split('.')[0]}'")

    @classmethod
    def validate_param(cls, arg: Any, param_def: dict) -> True:
        """Validates that the given argument matches the definition of the param
        Args:
            arg (Any): Argument to be validated
            param_def (dict): Definition of the parameter
        
        Raises:
            TypeError: Invalid argument

        Returns:
            True if argument is valid for the parameter definition given
        """
        # 1. Check if argument is None and parameter is required
        if arg is None and param_def[cls.NULL_KEY]:
            return True

        # 2. Get type of param for comparison
        if '[' in param_def[cls.TYPE_KEY]:
            param_type = getattr(
                builtins,
                param_def[cls.TYPE_KEY].split(
                    '['
                )[0]
            )
            param_item_type = getattr(
                builtins,
                param_def[cls.TYPE_KEY].split(
                    '['
                )[1][:-1]
            )
        else:
            param_type = getattr(builtins, param_def[cls.TYPE_KEY])
            param_item_type = None

        # 3. Check argument is of correct type
        if not isinstance(arg, param_type):
            raise TypeError(f"Expected {param_def[cls.TYPE_KEY]} for arg "
                f"{param_def[cls.NAME_KEY]}, got {type(arg).__name__}")

        if param_item_type is not None \
            and not all(
                isinstance(elem, param_item_type) for elem in arg
            ):
            raise TypeError(f"Expected {param_def[cls.TYPE_KEY]} for arg "
                f"{param_def[cls.NAME_KEY]}, got wrong item type")

        # 4. Check that we are not allowing an empty string if an argument
        # cannot be null
        if param_type in (list, dict, str) \
            and not param_def[cls.NULL_KEY] \
            and len(arg) == 0:
            raise TypeError(f"Expected non-empty {param_type.__name__} for arg "
                f"{param_def[cls.NAME_KEY]}, got empty {type(arg).__name__}")
        
        # Argument is valid for parameter if we haven't raise issue yet
        return True


    def __call__(self, *args, **kwargs) -> Any:
        """Calls self.__send with the arguments provided after validation

        We validate the arguments passed and if they are valid we pass them to
        self.__send

        Returns:
            Result of calling self.__send with *args and **kwargs

        TODO handle errors returned from API
        TODO be aware that an empty dictionary will pass the 'required' test
        """
        method = self.METHODS[self.__name]
        # 1. Validate we have all required arguments
        current_param = 0
        params = method[self.PARAM_KEY]
        # 1a. Positional arguments first
        for arg in args:
            # How many params have we tried to use
            if len(params) == current_param:
                raise TypeError(f"{self.__name} expected at most {len(params)}"
                    f" arguments, got {len(args) + len(kwargs)}")
            param_def = params[current_param]
            self.validate_param(arg, param_def)
            current_param += 1

        params_to_submit = list(args)
        
        # 1b. Keywords next
        param_pool = {
            p[self.NAME_KEY] : {**p, **{'index': i + current_param}} 
            for i, p in enumerate(params[current_param:])
        }
        for kwarg in kwargs:
            if len(params) == current_param:
                raise TypeError(f"{self.__name} expected at most {len(params)}"
                    f" arguments, got {len(args) + len(kwargs)}")
            param_def = param_pool.get(kwarg)
            if param_def is None:
                raise TypeError(f"{self.__name}() got an unexpected keyword "
                    f"argument '{kwarg}'")
            self.validate_param(kwargs[kwarg], param_def)
            current_param += 1

        params_to_submit += [
            kwargs[p[self.NAME_KEY]] for p in param_pool.values()
            if p[self.NAME_KEY] in kwargs
        ]

        # 1c. Add null/default for required params not accounted for 
        # that accept it
        for p in param_pool.values():
            if p[self.REQUIRED_KEY] \
                and (
                    p[self.NULL_KEY]
                    or p.get(self.DEFAULT_KEY)
                ) \
                and p[self.NAME_KEY] not in kwargs:
                params_to_submit.insert(
                    p['index'],
                    p.get(self.DEFAULT_KEY)
                )
                current_param += 1
            elif p[self.REQUIRED_KEY] \
                and not (
                    p[self.NULL_KEY]
                    or p.get(self.DEFAULT_KEY)
                ) \
                and p[self.NAME_KEY] not in kwargs:
                raise TypeError(f"{self.__name} missing argument '"
                    f"{p[self.NAME_KEY]}'")
                
        # 2. Call the function
        return self.__send(*params_to_submit)



# ---------------------------------
# ---- Setup and configuration ----
# ---------------------------------
SUPPORTED_METHODS: dict
BASE_DIR = pathlib.Path(__file__).resolve().parent
with open(BASE_DIR / 'supported_methods.json') as methods_file:
    SUPPORTED_METHODS = json.loads(methods_file.read())
_SupportedMethod.METHODS = SUPPORTED_METHODS

"""Tests the classes in pyovpn_as.api.rpc 
"""
import unittest
import unittest.mock

from pyovpn_as.api import rpc

@unittest.mock.patch.dict(
    rpc._SupportedMethod.METHODS, {
        'method_name': 'test'
    }, clear=True
)
class TestSupportedMethodInit(unittest.TestCase):
    """Tests the functionality of the __init__ method in the _SupportedMethod
       class
    """
    KNOWN_METHOD = 'method_name'

    def test_supported_method_init_wrong_name_raises_AttributeError(self):
        """Tests that an AttributeError is raised when a method name is given
           that is not supported.
        """
        with self.assertRaisesRegex(
            AttributeError,
            "object has no attribute 'not_a_name'"
        ):
            rpc._SupportedMethod(None, 'not_a_name')
    
    def test_supported_method_init_right_name_raises_nothing(self):
        """Tests that an object is created successfully when a method name is
           supported
        """
        self.assertIsInstance(
            rpc._SupportedMethod(None, self.KNOWN_METHOD),
            rpc._SupportedMethod
        )


@unittest.mock.patch.dict('pyovpn_as.api.rpc._SupportedMethod.METHODS', {
    "TestMethod": {
        rpc._SupportedMethod.PARAM_KEY: [
            {
                rpc._SupportedMethod.NAME_KEY: "bool",
                rpc._SupportedMethod.TYPE_KEY: "bool",
                rpc._SupportedMethod.NULL_KEY: False
            },
            {
                rpc._SupportedMethod.NAME_KEY: "int",
                rpc._SupportedMethod.TYPE_KEY: "int",
                rpc._SupportedMethod.NULL_KEY: False
            },
            {
                rpc._SupportedMethod.NAME_KEY: "float",
                rpc._SupportedMethod.TYPE_KEY: "float",
                rpc._SupportedMethod.NULL_KEY: False
            },
            {
                rpc._SupportedMethod.NAME_KEY: "str",
                rpc._SupportedMethod.TYPE_KEY: "str",
                rpc._SupportedMethod.NULL_KEY: False
            },
            {
                rpc._SupportedMethod.NAME_KEY: "str - null",
                rpc._SupportedMethod.TYPE_KEY: "str",
                rpc._SupportedMethod.NULL_KEY: True
            },
            {
                rpc._SupportedMethod.NAME_KEY: "list[str]",
                rpc._SupportedMethod.TYPE_KEY: "list[str]",
                rpc._SupportedMethod.NULL_KEY: False
            },
            {
                rpc._SupportedMethod.NAME_KEY: "list[str] - null",
                rpc._SupportedMethod.TYPE_KEY: "list[str]",
                rpc._SupportedMethod.NULL_KEY: True
            },
            {
                rpc._SupportedMethod.NAME_KEY: "dict[str]",
                rpc._SupportedMethod.TYPE_KEY: "dict[str]",
                rpc._SupportedMethod.NULL_KEY: False
            },
            {
                rpc._SupportedMethod.NAME_KEY: "dict[str] - null",
                rpc._SupportedMethod.TYPE_KEY: "dict[str]",
                rpc._SupportedMethod.NULL_KEY: True
            },
        ] 
    }
}, clear=True)
class TestSupportedMethodValidateParam(unittest.TestCase):
    """Tests the functionality of rpc._SupportedMethod.validate_param
    """
    # ------------------------------
    # ---- bool 
    # ------------------------------
    def test_bool_param_bool_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][0]
        self.assertTrue(
            rpc._SupportedMethod.validate_param(True, param)
        )
    
    def test_bool_param_non_bool_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][0]
        with self.assertRaisesRegex(
            TypeError, 'Expected bool for arg bool, got int'
        ):
            rpc._SupportedMethod.validate_param(3, param)
    
    # ------------------------------
    # ---- int 
    # ------------------------------
    def test_int_param_int_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][1]
        self.assertTrue(
            rpc._SupportedMethod.validate_param(3, param)
        )
    
    def test_int_param_non_int_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][1]
        with self.assertRaisesRegex(
            TypeError, 'Expected int for arg int, got str'
        ):
            rpc._SupportedMethod.validate_param('test', param)
    
    # ------------------------------
    # ---- float 
    # ------------------------------
    def test_float_param_float_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][2]
        self.assertTrue(
            rpc._SupportedMethod.validate_param(3.2, param)
        )
    
    def test_float_param_non_float_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][2]
        with self.assertRaisesRegex(
            TypeError, 'Expected float for arg float, got str'
        ):
            rpc._SupportedMethod.validate_param('test', param)
    
    # ------------------------------
    # ---- str 
    # ------------------------------
    def test_str_param_str_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][3]
        self.assertTrue(
            rpc._SupportedMethod.validate_param('test', param)
        )
    
    def test_str_param_non_str_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][3]
        with self.assertRaisesRegex(
            TypeError, 'Expected str for arg str, got int'
        ):
            rpc._SupportedMethod.validate_param(3, param)

    def test_required_param_none_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][3]
        with self.assertRaisesRegex(
            TypeError, 'Expected str for arg str, got NoneType'
        ):
            rpc._SupportedMethod.validate_param(None, param)

    def test_required_str_param_none_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][3]
        with self.assertRaisesRegex(
            TypeError, 'Expected non-empty str for arg str, got empty str'
        ):
            rpc._SupportedMethod.validate_param('', param)

    def test_optional_param_none_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][4]
        self.assertTrue(
            rpc._SupportedMethod.validate_param(None, param)
        )

    def test_optional_param_empty_str_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][4]
        self.assertTrue(
            rpc._SupportedMethod.validate_param('', param)
        )
    
    # ------------------------------
    # ---- list 
    # ------------------------------
    def test_list_param_list_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][5]
        self.assertTrue(
            rpc._SupportedMethod.validate_param(['test',], param)
        )
    
    def test_list_param_non_list_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][5]
        with self.assertRaisesRegex(
            TypeError, 'Expected list\[str] for arg list\[str], got str'
        ):
            rpc._SupportedMethod.validate_param('test', param)
    
    def test_list_str_param_non_list_str_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][5]
        with self.assertRaisesRegex(
            TypeError,
            'Expected list\[str] for arg list\[str], got wrong item type'
        ):
            rpc._SupportedMethod.validate_param(['test', 3], param)
    
    def test_required_list_param_empty_list_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][5]
        with self.assertRaisesRegex(
            TypeError,
            'Expected non-empty list for arg list\[str], got empty list'
        ):
            rpc._SupportedMethod.validate_param([], param)

    def test_optional_list_param_empty_list_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][6]
        self.assertTrue(
            rpc._SupportedMethod.validate_param([], param)
        )
    
    # ------------------------------
    # ---- dict 
    # ------------------------------
    def test_dict_param_dict_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][7]
        self.assertTrue(
            rpc._SupportedMethod.validate_param({'test': 'test'}, param)
        )
    
    def test_dict_param_non_dict_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][7]
        with self.assertRaisesRegex(
            TypeError, 'Expected dict\[str] for arg dict\[str], got str'
        ):
            rpc._SupportedMethod.validate_param('test', param)
    
    def test_dict_str_param_non_dict_str_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][7]
        with self.assertRaisesRegex(
            TypeError,
            'Expected dict\[str] for arg dict\[str], got wrong item type'
        ):
            rpc._SupportedMethod.validate_param({'test': 'test', 3: 3}, param)
    
    def test_required_dict_param_empty_dict_arg_raises_TypeError(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][7]
        with self.assertRaisesRegex(
            TypeError,
            'Expected non-empty dict for arg dict\[str], got empty dict'
        ):
            rpc._SupportedMethod.validate_param({}, param)

    def test_optional_dict_param_empty_dict_arg_passes_validation(self):
        param = rpc._SupportedMethod.METHODS['TestMethod']['params'][8]
        self.assertTrue(
            rpc._SupportedMethod.validate_param({}, param)
        )

test_method_def = {
    "TestMethod": {
        rpc._SupportedMethod.PARAM_KEY: [
            {
                rpc._SupportedMethod.NAME_KEY: "required",
                rpc._SupportedMethod.REQUIRED_KEY: True,
                rpc._SupportedMethod.NULL_KEY: False,
            },
            {
                rpc._SupportedMethod.NAME_KEY: "required_null",
                rpc._SupportedMethod.REQUIRED_KEY: True,
                rpc._SupportedMethod.NULL_KEY: True,
            },
            {
                rpc._SupportedMethod.NAME_KEY: "required_default",
                rpc._SupportedMethod.REQUIRED_KEY: True,
                rpc._SupportedMethod.NULL_KEY: False,
                rpc._SupportedMethod.DEFAULT_KEY: "default",
            },
            {
                rpc._SupportedMethod.NAME_KEY: "required_null_default",
                rpc._SupportedMethod.REQUIRED_KEY: True,
                rpc._SupportedMethod.NULL_KEY: True,
                rpc._SupportedMethod.DEFAULT_KEY: "default",
            },
            {
                rpc._SupportedMethod.NAME_KEY: "not_required",
                rpc._SupportedMethod.REQUIRED_KEY: False,
                rpc._SupportedMethod.NULL_KEY: False,
            },
            {
                rpc._SupportedMethod.NAME_KEY: "not_required_2",
                rpc._SupportedMethod.REQUIRED_KEY: False,
                rpc._SupportedMethod.NULL_KEY: False,
            }
        ]
    }
}

@unittest.mock.patch.dict(
    'pyovpn_as.api.rpc._SupportedMethod.METHODS',
    test_method_def,
    clear=True
)
@unittest.mock.patch.object(
    rpc._SupportedMethod,
    'validate_param',
    unittest.mock.Mock(return_value=True)
)
class TestSupportedMethodCall(unittest.TestCase):
    """Tests the functionality of rpc._SupportedMethod.__call__
    """
    @unittest.mock.patch.dict(
        'pyovpn_as.api.rpc._SupportedMethod.METHODS',
        test_method_def,
        clear=True
    )
    def setUp(self):
        self.send_mock = unittest.mock.Mock(return_value='test')
        self.method = rpc._SupportedMethod(self.send_mock, 'TestMethod')
    
    def test_more_args_than_params_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod expected at most [0-9]+ arguments, got [0-9]+"
        ):
            self.method(1, 2, 3, 4, 5, 6, 7)

    def test_more_kwargs_than_params_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod expected at most [0-9]+ arguments, got [0-9]+"
        ):
            self.method(
                required=1,
                required_null=2,
                required_default=3,
                required_null_default=4,
                not_required=5,
                not_required_2=6,
                doesnt_exist=7
            )
    
    def test_more_args_kwargs_than_params_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod expected at most [0-9]+ arguments, got [0-9]+"
        ):
            self.method(
                1, 2, 3,
                required_null_default=4,
                not_required=5,
                not_required_2=6,
                doesnt_exist=7
            )

    def test_duplicate_arg_kwarg_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod\(\) got multiple values for argument 'required'"
        ):
            self.method(
                1, 2, 3, 4,
                required='duplicate value'
            )
    
    def test_non_existent_kwarg_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod\(\) got an unexpected keyword argument 'unexpected'"
        ):
            self.method(
                1, 2, 3, 4,
                unexpected='wow, this is unexpected'
            )
    
    def test_required_no_default_not_null_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod missing argument 'required'"
        ):
            self.method(
                required_null=2,
                required_default=3,
                required_null_default=4,
                not_required=5
            )
    
    def test_required_no_default_null_calls_with_null(self):
        self.method(
            required=1,
            required_default=3,
            required_null_default=4,
            not_required=5
        )
        self.send_mock.assert_called_with(1, None, 3, 4, 5)
    
    def test_required_default_no_null_calls_with_default(self):
        self.method(
            required=1,
            required_null=2,
            required_null_default=4,
            not_required=5
        )
        self.send_mock.assert_called_with(1, 2, 'default', 4, 5)
    
    def test_required_default_null_calls_with_default(self):
        self.method(
            required=1,
            required_null=2,
            required_default=3,
            not_required=5
        )
        self.send_mock.assert_called_with(1, 2, 3, 'default', 5)

    def test_skip_not_required_parameter_raises_TypeError(self):
        with self.assertRaisesRegex(
            TypeError,
            "TestMethod missing argument 'not_required'"
        ):
            self.method(
                required=1,
                required_null=2,
                required_default=3,
                required_null_default=4,
                not_required_2=6
            )



if __name__ == '__main__':
    unittest.main()
        
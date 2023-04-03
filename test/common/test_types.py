# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import pathlib2 as pathlib
except ImportError:
    import pathlib

import collections

from test.common.classes import (
    TestEnumNamedParams,
    TestEnumNumericParams,
    TestEnumOidParams,
    TestEnumStringParams,
    EnumTest,
)

import pyfakefs.fake_filesystem_unittest

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataEnumCodedBase, CryptoDataEnumOIDBase, convert_enum


class TestEnumConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_enum(EnumTest)(original_value)
        self.assertEqual(id(original_value), id(convert_enum(EnumTest)(converted_value)))

    def test_error_invalid_value(self):
        original_value = 'not in enum'
        converted_value = convert_enum(EnumTest)(original_value)
        self.assertEqual(id(converted_value), id(convert_enum(EnumTest)(converted_value)))

    def test_none(self):
        converted_value = convert_enum(EnumTest)(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        original_value = 'STRING'
        converted_value = convert_enum(EnumTest)(original_value)

        self.assertEqual(converted_value, EnumTest.STRING)

    def test_repr(self):
        self.assertEqual(repr(convert_enum(EnumTest)), '<enum converter>')


class TestCryptoDataBase(pyfakefs.fake_filesystem_unittest.TestCase):
    def setUp(self):  # pylint: disable=invalid-name
        self.setUpPyfakefs()

    @staticmethod
    def _get_json_path_as_str(param_class):
        return str(CryptoDataEnumBase.get_json_path(param_class))


class TestCryptoDataEnumNamed(TestCryptoDataBase):
    def test_str(self):
        self.fs.create_file(
            self._get_json_path_as_str(TestEnumNamedParams),
            contents='{"NAME": {"name": "name", "long_name": "long_name"}}'
        )
        test_enum_named_class = CryptoDataEnumBase(
            'test_enum_named_class', CryptoDataEnumBase.get_json_records(TestEnumNamedParams)
        )
        self.assertEqual(str(test_enum_named_class.NAME.value), 'name')


class TestCryptoDataEnumBase(TestCryptoDataBase):
    def test_error_get_json_path(self):
        with self.assertRaises(TypeError) as context_manager:
            self._get_json_path_as_str(TestCryptoDataEnumBase)
        self.assertEqual(context_manager.exception.args, (TestCryptoDataEnumBase, ))

    def test_get_json_path(self):
        json_path = CryptoDataEnumBase.get_json_path(TestEnumNamedParams)
        self.assertTrue(isinstance(json_path, pathlib.Path))
        self.assertEqual(json_path.name, 'test-enum-named.json')

    def test_get_records(self):
        self.fs.create_file(
             self._get_json_path_as_str(TestEnumNamedParams),
             contents="""
                 {
                     "NAME": {
                         "_hidden_key_1": "value",
                         "name": "name",
                         "_hidden_key_2": "value",
                         "long-name": "long-name"
                     }
                 }
             """
        )
        json_records = CryptoDataEnumBase.get_json_records(TestEnumNamedParams)
        self.assertEqual(json_records, collections.OrderedDict([
             ('NAME', TestEnumNamedParams(name='name', long_name='long-name')),
        ]))


class TestCryptoDataEnumCodedBase(TestCryptoDataBase):
    def test_from_code(self):
        self.fs.create_file(
             self._get_json_path_as_str(TestEnumNumericParams),
             contents="""
                 {
                     "ONE": {
                         "code": 1
                     },
                     "TWO": {
                         "code": 2
                     }
                 }
             """
        )
        test_enum_numeric_class = CryptoDataEnumCodedBase(
            'test_enum_numeric_class', CryptoDataEnumCodedBase.get_json_records(TestEnumNumericParams)
        )
        self.assertEqual(test_enum_numeric_class.from_code(1), test_enum_numeric_class.ONE)
        self.assertEqual(test_enum_numeric_class.from_code(2), test_enum_numeric_class.TWO)
        with self.assertRaises(InvalidValue) as context_manager:
            test_enum_numeric_class.from_code(3)
        self.assertEqual(context_manager.exception.value, 3)


class TestCryptoDataEnumOidBase(TestCryptoDataBase):
    def test_from_oid(self):
        self.fs.create_file(
             self._get_json_path_as_str(TestEnumOidParams),
             contents="""
                 {
                     "ONE": {
                         "name": "one",
                         "long_name": null,
                         "oid": "1.1.1.1.1.1"
                     },
                     "TWO": {
                         "name": "two",
                         "long_name": null,
                         "oid": "2.2.2.2.2.2"
                     }
                 }
             """
        )
        test_enum_oid_class = CryptoDataEnumOIDBase(
            'test_enum_oid_class', CryptoDataEnumCodedBase.get_json_records(TestEnumOidParams)
        )
        self.assertEqual(test_enum_oid_class.from_oid('1.1.1.1.1.1'), test_enum_oid_class.ONE)
        self.assertEqual(test_enum_oid_class.from_oid('2.2.2.2.2.2'), test_enum_oid_class.TWO)


class TestCryptoDataEnumNumeric(TestCryptoDataBase):
    def test_error_code_negativ(self):
        self.fs.create_file(self._get_json_path_as_str(TestEnumNumericParams), contents='{"NAME": {"code": -1}}')
        with self.assertRaises(ValueError) as context_manager:
            CryptoDataEnumBase(
                'TestEnumNumeric', CryptoDataEnumBase.get_json_records(TestEnumNumericParams)
            )
        self.assertEqual(context_manager.exception.args, (-1, ))

    def test_error_code_too_large(self):
        self.fs.create_file(self._get_json_path_as_str(TestEnumNumericParams), contents='{"NAME": {"code": 256}}')
        with self.assertRaises(ValueError) as context_manager:
            CryptoDataEnumBase(
                'TestEnumNumeric', CryptoDataEnumBase.get_json_records(TestEnumNumericParams)
            )
        self.assertEqual(context_manager.exception.args, (256, ))

    def test_error_non_numeric(self):
        self.fs.create_file(
            self._get_json_path_as_str(TestEnumNumericParams),
            contents='{"NAME": {"code": "non-numeric"}}'
        )
        with self.assertRaises(ValueError) as context_manager:
            CryptoDataEnumBase(
                'TestEnumNumeric', CryptoDataEnumBase.get_json_records(TestEnumNumericParams)
            )
        self.assertEqual(context_manager.exception.args, ('non-numeric', ))


class TestCryptoDataEnumString(TestCryptoDataBase):
    def test_str(self):
        self.fs.create_file(
            self._get_json_path_as_str(TestEnumStringParams),
            contents='{"NAME": {"code": "string"}}'
        )
        test_enum_string_class = CryptoDataEnumBase(
            'test_enum_string_class', CryptoDataEnumBase.get_json_records(TestEnumStringParams)
        )

        self.assertEqual(str(test_enum_string_class.NAME.value), 'string')

    def test_asdict(self):
        self.fs.create_file(
            self._get_json_path_as_str(TestEnumStringParams),
            contents='{"NAME": {"code": "dict"}}'
        )
        test_enum_string_class = CryptoDataEnumBase(
            'test_enum_string_class', CryptoDataEnumBase.get_json_records(TestEnumStringParams)
        )

        self.assertEqual(test_enum_string_class.NAME.value._asdict(), 'dict')

    def test_get_code_size(self):
        self.fs.create_file(
            self._get_json_path_as_str(TestEnumStringParams),
            contents='{"NAME": {"code": "four"}}'
        )
        test_enum_string_class = CryptoDataEnumBase(
            'test_enum_string_class', CryptoDataEnumBase.get_json_records(TestEnumStringParams)
        )

        self.assertEqual(test_enum_string_class.NAME.value.get_code_size(), 4)

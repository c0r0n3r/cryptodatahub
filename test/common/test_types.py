# -*- coding: utf-8 -*-

import collections
import datetime
import pathlib
import unittest

from test.common.classes import (
    TestEnumNamedParams,
    TestEnumNumericParams,
    TestEnumOidParams,
    TestEnumStringParams,
    TestJsonObject,
    TestJsonObjectComplex,
    EnumIntTest,
    EnumTest,
)

import dateutil
import pyfakefs.fake_filesystem_unittest
import urllib3

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import (
    Base64Data,
    ClientVersion,
    CryptoDataEnumBase,
    CryptoDataEnumCodedBase,
    CryptoDataEnumOIDBase,
    convert_big_enum,
    convert_base64_data,
    convert_client_version,
    convert_datetime,
    convert_dict_to_object,
    convert_enum,
    convert_iterable,
    convert_mapping,
    convert_url,
    convert_variadic,
    convert_value_to_object,
)


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


class TestDateTimeConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1
        converted_value = convert_datetime(None)(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_error_invalid_value(self):
        original_value = 'not a date'
        converted_value = convert_datetime(None)(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_none(self):
        converted_value = convert_datetime(None)(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        original_value = '2023-04-15T20:01:02+00:00'
        converted_value = convert_datetime(None)(original_value)

        self.assertEqual(converted_value, datetime.datetime(2023, 4, 15, 20, 1, 2, tzinfo=dateutil.tz.UTC))
        self.assertEqual(id(converted_value), id(convert_datetime(None)(converted_value)))

        original_value = '21/11/06 16:30'
        converted_value = convert_datetime('%d/%m/%y %H:%M')(original_value)

        self.assertEqual(converted_value,  datetime.datetime(2006, 11, 21, 16, 30))
        self.assertEqual(id(converted_value), id(convert_datetime(None)(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_datetime(None)), '<datetime converter>')


class TestBase64Data(unittest.TestCase):
    def test_str(self):
        self.assertEqual(str(Base64Data(b'light work.')), 'bGlnaHQgd29yay4=')

    def test_asdict(self):
        base64_data = Base64Data(b'light work.')
        self.assertEqual(str(base64_data), base64_data._asdict())


class TestBase64DataConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 'not a binary value'
        converted_value = convert_base64_data()(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_error_invalid_value(self):
        original_value = 'not a base64 str'
        converted_value = convert_base64_data()(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_error_invalid_padding(self):
        original_value = 'invalid padding'
        converted_value = convert_base64_data()(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_none(self):
        converted_value = convert_base64_data()(None)
        self.assertEqual(converted_value, None)

    def test_binary_value(self):
        original_value = bytearray(b'binary value')
        converted_value = convert_base64_data()(original_value)
        self.assertNotEqual(id(original_value), id(converted_value))

    def test_convert(self):
        original_value = 'bGlnaHQgd29yay4='
        converted_value = convert_base64_data()(original_value)

        self.assertEqual(converted_value, Base64Data(b'light work.'))
        self.assertEqual(id(converted_value), id(convert_base64_data()(converted_value)))

        original_value = 'bGlnaHQgd29yay4=='
        converted_value = convert_base64_data()(original_value)

        self.assertEqual(converted_value, Base64Data(b'light work.'))
        self.assertEqual(id(converted_value), id(convert_base64_data()(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_base64_data()), '<base64 data converter>')


class TestDictToObjectConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_dict_to_object(TestJsonObject)(original_value)
        self.assertEqual(original_value, converted_value)

    def test_error_invalid_value(self):
        original_value = 1.0
        converted_value = convert_dict_to_object(TestJsonObject)(original_value)
        self.assertEqual(original_value, converted_value)

    def test_none(self):
        converted_value = convert_dict_to_object(TestJsonObject)(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        original_value = {
            'attr_simple': 1,
            'attr_iterable': [1, 2, 3, 4],
            'attr_complex': {'attr': 'value'},
        }

        converted_value = convert_dict_to_object(TestJsonObject)(original_value)

        self.assertEqual(
            converted_value,
            TestJsonObject(
                attr_simple=1,
                attr_iterable=[1, 2, 3, 4],
                attr_complex=TestJsonObjectComplex('value'),
            )
        )
        self.assertEqual(id(converted_value), id(convert_dict_to_object(str)(converted_value)))

    def test_asdict(self):
        self.assertEqual(
            TestJsonObject(
                attr_simple=1,
                attr_iterable=[1, 2, 3, 4],
                attr_complex=TestJsonObjectComplex('value'),
            )._asdict(),
            collections.OrderedDict([
                ('attr_simple', 1),
                ('attr_iterable', [1, 2, 3, 4]),
                ('attr_complex', {'attr': 'value'}),
            ])
        )

    def test_repr(self):
        self.assertEqual(repr(convert_dict_to_object(str)), '<dict to object converter>')


class TestValueToObjectConverter(unittest.TestCase):
    def test_none(self):
        converted_value = convert_value_to_object(TestJsonObjectComplex)(None)
        self.assertEqual(converted_value, None)

    def test_convert_object_class(self):
        original_value = TestJsonObjectComplex('value')
        converted_value = convert_value_to_object(TestJsonObjectComplex)(original_value)
        self.assertEqual(original_value, converted_value)

    def test_convert_converter(self):
        original_value = '1970-01-01'
        converted_value = convert_value_to_object(TestJsonObjectComplex, convert_datetime())(original_value)
        self.assertEqual(converted_value.attr, datetime.datetime(1970, 1, 1, 0, 0))

    def test_repr(self):
        self.assertEqual(repr(convert_value_to_object(str)), '<value to object converter>')


class TestBigNumberConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_big_enum()(original_value)
        self.assertEqual(id(original_value), id(convert_big_enum()(converted_value)))

    def test_error_invalid_value(self):
        original_value = 'not a big number'
        converted_value = convert_big_enum()(original_value)
        self.assertEqual(id(converted_value), id(convert_big_enum()(converted_value)))

        original_value = [1, 2, 3, 4]
        converted_value = convert_big_enum()(original_value)
        self.assertEqual(id(converted_value), id(convert_big_enum()(converted_value)))

    def test_none(self):
        converted_value = convert_big_enum()(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        # C code-style
        original_value = [
            '0x01, 0x23',
            '0x45, 0x67'
        ]
        converted_value = convert_big_enum()(original_value)
        self.assertEqual(converted_value, 0x1234567)

        # RFC-style
        original_value = [
            '01234567 89abcdef',
            '89abcdef 01234567',
        ]
        converted_value = convert_big_enum()(original_value)
        self.assertEqual(converted_value, 0x0123456789abcdef89abcdef01234567)

    def test_repr(self):
        self.assertEqual(repr(convert_big_enum()), '<big number converter>')


class TestIterableConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_iterable(str)(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_error_invalid_value(self):
        original_value = 1.0
        converted_value = convert_iterable(str)(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_none(self):
        converted_value = convert_iterable(str)(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        original_value = [1, 2, 3]
        converted_value = convert_iterable(str)(original_value)

        self.assertEqual(converted_value, ['1', '2', '3'])
        self.assertEqual(id(converted_value), id(convert_iterable(str)(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_iterable(str)), '<iterable converter>')


class TestMappingConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_mapping(str)(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_error_invalid_value_key(self):
        original_value = {'not a number': 1}
        converted_value = convert_mapping(key_converter=int)(original_value)
        self.assertEqual(original_value, converted_value)

    def test_error_invalid_value_value(self):
        original_value = {1: 'not a number'}
        converted_value = convert_mapping(key_converter=int)(original_value)
        self.assertEqual(original_value, converted_value)

    def test_none(self):
        converted_value = convert_mapping(str)(None)
        self.assertEqual(converted_value, None)

    def test_convert_key(self):
        original_value = {1: '1', 2: '2', 3: '3'}
        converted_value = convert_mapping(key_converter=str)(original_value)

        self.assertEqual(converted_value, {'1': '1', '2': '2', '3': '3'})
        self.assertNotEqual(id(converted_value), id(convert_mapping(str)(converted_value)))

    def test_convert_value(self):
        original_value = {'1': 1, '2': 2, '3': 3}
        converted_value = convert_mapping(value_converter=str)(original_value)

        self.assertEqual(converted_value, {'1': '1', '2': '2', '3': '3'})
        self.assertNotEqual(id(converted_value), id(convert_mapping(str)(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_mapping(str)), '<mapping converter>')


class TestUrlConverter(unittest.TestCase):
    def test_error_invalid_value(self):
        original_value = 'https://example.com:123456'
        converted_value = convert_url()(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_none(self):
        converted_value = convert_url()(None)
        self.assertEqual(converted_value, None)

    def test_convert_value(self):
        original_value = 'https://example.com'
        converted_value = convert_url()(original_value)

        self.assertEqual(
            converted_value,
            urllib3.util.url.Url(scheme='https', host='example.com')
        )
        self.assertEqual(id(converted_value), id(convert_url()(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_url()), '<url converter>')


class TestClientVariadicConverter(unittest.TestCase):
    def test_repr(self):
        self.assertEqual(repr(convert_variadic([])), '<variadic converter>')

    def test_error_invalid_value(self):
        original_value = 'non-enum'
        converted_value = convert_variadic([convert_enum(EnumIntTest)])(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_none(self):
        converted_value = convert_variadic([])(None)
        self.assertEqual(converted_value, None)

    def test_convert_value(self):
        original_value = 'ONE'
        converted_value = convert_variadic([convert_enum(EnumIntTest)])(original_value)

        self.assertEqual(converted_value, EnumIntTest.ONE)
        self.assertEqual(id(converted_value), id(convert_variadic([convert_enum(EnumIntTest)])(converted_value)))

        original_value = 'NONE'
        converted_value = convert_variadic([convert_enum(EnumIntTest), convert_enum(EnumTest)])(original_value)

        self.assertEqual(converted_value, EnumTest.NONE)
        self.assertEqual(
            id(converted_value),
            id(convert_variadic([convert_enum(EnumIntTest), convert_enum(EnumTest)])(converted_value))
        )


class TestClientVersionConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_client_version()(original_value)
        self.assertEqual(id(original_value), id(converted_value))

    def test_error_invalid_value(self):
        original_value = 'neither a single not a dotted number'
        converted_value = convert_client_version()(original_value)
        self.assertEqual(original_value, converted_value)

    def test_none(self):
        converted_value = convert_client_version()(None)
        self.assertEqual(converted_value, None)

    def test_convert_value(self):
        original_value = '1'
        converted_value = convert_client_version()(original_value)

        self.assertEqual(converted_value, ClientVersion((1, )))
        self.assertEqual(id(converted_value), id(convert_client_version()(converted_value)))

        original_value = '1.2.3'
        converted_value = convert_client_version()(original_value)

        self.assertEqual(converted_value, ClientVersion((1, 2, 3)))
        self.assertEqual(id(converted_value), id(convert_client_version()(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_client_version()), '<client version converter>')


class TestCryptoDataBase(pyfakefs.fake_filesystem_unittest.TestCase):
    def setUp(self):  # pylint: disable=invalid-name
        self.setUpPyfakefs()

    def _set_json(self, param_class, json_object):
        self.fs.create_dir(str(CryptoDataEnumBase.get_json_path(param_class).parent))
        CryptoDataEnumBase.set_json(param_class, json_object)


class TestCryptoDataEnumNamed(TestCryptoDataBase):
    def test_str(self):
        self._set_json(
            TestEnumNamedParams,
            {'NAME': {'name': 'name', 'long_name': 'long_name'}}
        )
        test_enum_named_class = CryptoDataEnumBase(
            'test_enum_named_class', CryptoDataEnumBase.get_json_records(TestEnumNamedParams)
        )
        self.assertEqual(str(test_enum_named_class.NAME.value), 'name')


class TestCryptoDataEnumBase(TestCryptoDataBase):
    def test_error_get_json_path(self):
        with self.assertRaises(TypeError) as context_manager:
            self._set_json(TestCryptoDataEnumBase, {})
        self.assertEqual(context_manager.exception.args, (TestCryptoDataEnumBase, ))

    def test_get_json_path(self):
        json_path = CryptoDataEnumBase.get_json_path(TestEnumNamedParams)
        self.assertTrue(isinstance(json_path, pathlib.Path))
        self.assertEqual(json_path.name, 'test-enum-named.json')

    def test_get_json(self):
        json_object = {
            'ONE': {
                'code': 1
            },
            'TWO': {
                'code': 2
            }
        }
        self._set_json(TestEnumNumericParams, json_object)
        self.assertEqual(CryptoDataEnumBase.get_json(TestEnumNumericParams), json_object)

    def test_get_records(self):
        json_object = {
            'NAME': {
                '_hidden_key_1': 'value',
                'name': 'name',
                '_hidden_key_2': 'value',
                'long-name': 'long-name'
            }
        }
        self._set_json(TestEnumNamedParams, json_object)
        json_records = CryptoDataEnumBase.get_json_records(TestEnumNamedParams)
        self.assertEqual(json_records, collections.OrderedDict([
             ('NAME', TestEnumNamedParams(name='name', long_name='long-name')),
        ]))


class TestCryptoDataEnumCodedBase(TestCryptoDataBase):
    def test_from_code(self):
        json_object = {
             'ONE': {
                 'code': 1
             },
             'TWO': {
                 'code': 2
             }
         }
        self._set_json(TestEnumNumericParams, json_object)
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
        json_object = {
            'ONE': {
                'name': 'one',
                'long_name': None,
                'oid': '1.1.1.1.1.1'
            },
            'TWO': {
                'name': 'two',
                'long_name': None,
                'oid': '2.2.2.2.2.2'
            }
        }
        self._set_json(TestEnumOidParams, json_object)
        test_enum_oid_class = CryptoDataEnumOIDBase(
            'test_enum_oid_class', CryptoDataEnumCodedBase.get_json_records(TestEnumOidParams)
        )
        self.assertEqual(test_enum_oid_class.from_oid('1.1.1.1.1.1'), test_enum_oid_class.ONE)
        self.assertEqual(test_enum_oid_class.from_oid('2.2.2.2.2.2'), test_enum_oid_class.TWO)


class TestCryptoDataEnumNumeric(TestCryptoDataBase):
    def test_error_code_negativ(self):
        self._set_json(TestEnumNumericParams, {'NAME': {'code': -1}})
        with self.assertRaises(ValueError) as context_manager:
            CryptoDataEnumBase(
                'TestEnumNumeric', CryptoDataEnumBase.get_json_records(TestEnumNumericParams)
            )
        self.assertEqual(context_manager.exception.args, (-1, ))

    def test_error_code_too_large(self):
        self._set_json(TestEnumNumericParams, {'NAME': {'code': 256}})
        with self.assertRaises(ValueError) as context_manager:
            CryptoDataEnumBase(
                'TestEnumNumeric', CryptoDataEnumBase.get_json_records(TestEnumNumericParams)
            )
        self.assertEqual(context_manager.exception.args, (256, ))

    def test_error_non_numeric(self):
        self._set_json(TestEnumNumericParams, {'NAME': {'code': 'non-numeric'}})
        with self.assertRaises(ValueError) as context_manager:
            CryptoDataEnumBase(
                'TestEnumNumeric', CryptoDataEnumBase.get_json_records(TestEnumNumericParams)
            )
        self.assertEqual(context_manager.exception.args, ('non-numeric', ))


class TestCryptoDataEnumString(TestCryptoDataBase):
    def test_str(self):
        self._set_json(TestEnumStringParams, {'NAME': {'code': 'string'}})
        test_enum_string_class = CryptoDataEnumBase(
            'test_enum_string_class', CryptoDataEnumBase.get_json_records(TestEnumStringParams)
        )

        self.assertEqual(str(test_enum_string_class.NAME.value), 'string')

    def test_asdict(self):
        self._set_json(TestEnumStringParams, {'NAME': {'code': 'dict'}})
        test_enum_string_class = CryptoDataEnumBase(
            'test_enum_string_class', CryptoDataEnumBase.get_json_records(TestEnumStringParams)
        )

        self.assertEqual(test_enum_string_class.NAME.value._asdict(), 'dict')

    def test_get_code_size(self):
        self._set_json(TestEnumStringParams, {'NAME': {'code': 'four'}})
        test_enum_string_class = CryptoDataEnumBase(
            'test_enum_string_class', CryptoDataEnumBase.get_json_records(TestEnumStringParams)
        )

        self.assertEqual(test_enum_string_class.NAME.value.get_code_size(), 4)

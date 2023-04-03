# -*- coding: utf-8 -*-

try:
    import unittest
except ImportError:
    import unittest2 as unittest

import abc
import codecs
import collections
import enum
import json

import attr
import six

from cryptodatahub.common.types import (
    CryptoDataParamsEnumNumeric,
    CryptoDataParamsEnumString,
    CryptoDataParamsOIDOptional,
    CryptoDataParamsNamed,
)


class EnumTest(enum.Enum):
    NONE = 'NONE'
    STRING = 'STRING'
    INT = 'INT'
    FLOAT = 'FLOAT'
    BOOL = 'BOOL'


class EnumIntTest(enum.IntEnum):
    ONE = 1
    TEN = 10


class TestEnumNamedParams(CryptoDataParamsNamed):
    pass


class TestEnumNumericParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 1


class TestEnumStringParams(CryptoDataParamsEnumString):
    pass


class TestEnumOidParams(CryptoDataParamsOIDOptional):
    pass


class TestClasses:
    class TestJsonBase(unittest.TestCase):
        @classmethod
        @abc.abstractmethod
        def _get_class(cls):
            raise NotImplementedError()

        @classmethod
        def _get_protected_names(cls):
            return set(['_standard', ])

        @classmethod
        def _get_params_class(cls):
            return type(list(cls._get_class())[0].value)

        def setUp(self):
            self.json_file = codecs.open(  # pylint: disable=consider-using-with
                str(self._get_class().get_json_path(self._get_params_class())), 'r', encoding='ascii'
            )
            self.json_data = json.load(self.json_file, object_pairs_hook=collections.OrderedDict)

        def tearDown(self):
            self.json_file.close()

        def test_json_file_format(self):
            wrong_indents = []
            tab_in_lines = []
            wrong_number_of_spces_after_colon = []
            whitespace_only_lines = []
            trailing_whitespaces = []

            self.json_file.seek(0)
            for index, line in enumerate(self.json_file):
                if not line.strip():
                    whitespace_only_lines.append(index + 1)
                try:
                    colon_index = line.index(':')
                    if line[colon_index + 1] != ' ':
                        wrong_number_of_spces_after_colon.append(index + 1)
                    if line[colon_index + 2] == ' ':
                        wrong_number_of_spces_after_colon.append(index + 1)
                except ValueError:
                    pass
                if '\t' in line:
                    tab_in_lines.append(index + 1)
                if line.startswith(' ') and (len(line) - len(line.lstrip())) % 4 != 0:
                    wrong_indents.append(index + 1)
                if len(line) - 1 != len(line.rstrip()):
                    trailing_whitespaces.append(index + 1)

            self.assertEqual(whitespace_only_lines, [])
            self.assertEqual(tab_in_lines, [])
            self.assertEqual(wrong_number_of_spces_after_colon, [])
            self.assertEqual(trailing_whitespaces, [])
            self.assertEqual(wrong_indents, [])

        def test_param_list_len(self):
            self.assertEqual(len(self._get_class()), len(self.json_data))

        def test_param_attribute_names_protected(self):
            protected_names = self._get_protected_names()

            self.assertEqual([
                name
                for name, item in self.json_data.items()
                if set(key for key in item.keys() if key.startswith('_')) in protected_names
            ], [])

        def test_param_attribute_order(self):
            attribute_names = [
                six.ensure_text(name)
                for name, attribute in attr.fields_dict(self._get_params_class()).items()
                if attribute.init
            ]

            self.assertEqual([
                name
                for name, item in self.json_data.items()
                if [key for key in item.keys() if not key.startswith(six.u('_'))] != attribute_names
            ], [])

            attribute_names_not_ordered = []
            for name, item in self.json_data.items():
                protected_count = 0
                for key in item.keys():
                    protected_count += 1
                    if not key.startswith('_'):
                        break

                public_count = 0
                for key in list(item.keys())[protected_count:]:
                    public_count += 1
                    if key.startswith('_'):
                        break

                if protected_count + public_count != len(item.keys()):
                    attribute_names_not_ordered.append(key)

            self.assertEqual(attribute_names_not_ordered, [])

    class TestJsonCodeStringBase(TestJsonBase):
        @classmethod
        @abc.abstractmethod
        def _get_class(cls):
            raise NotImplementedError()

    class TestJsonCodeNumericBase(TestJsonBase):
        @classmethod
        @abc.abstractmethod
        def _get_class(cls):
            raise NotImplementedError()

        def test_code_size(self):
            self.assertGreater(self._get_params_class().get_code_size(), 0)

        @classmethod
        def _get_protected_names(cls):
            return super(TestClasses.TestJsonCodeNumericBase, cls)._get_protected_names() | set(['_code_in_hex', ])

        def test_param_attribute_value_code_in_hex(self):
            self.assertEqual([
                item['_code_in_hex']
                for item in self.json_data.values()
                if int(item['code']) != int(item['_code_in_hex'], 16)
            ], [])

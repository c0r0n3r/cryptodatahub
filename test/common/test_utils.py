# -*- coding: utf-8 -*-

import unittest

import six

from cryptodatahub.common.utils import bytes_from_hex_string, bytes_to_hex_string, name_to_enum_item_name


class TestBytesToHexString(unittest.TestCase):
    def test_separator(self):
        self.assertEqual(bytes_to_hex_string(b''), '')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef'), 'DEADBEEF')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef', separator=':'), 'DE:AD:BE:EF')

    def test_lowercase(self):
        self.assertEqual(bytes_to_hex_string(b''), '')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef'), 'DEADBEEF')
        self.assertEqual(bytes_to_hex_string(b'\xde\xad\xbe\xef', lowercase=True), 'deadbeef')


class TestBytesFromHexString(unittest.TestCase):
    def test_error_odd_length_string(self):
        with self.assertRaises(ValueError) as context_manager:
            bytes_from_hex_string('0d:d')
        self.assertEqual(type(context_manager.exception), ValueError)

    def test_error_non_hex_string(self):
        with self.assertRaises(ValueError) as context_manager:
            bytes_from_hex_string('no:th:ex')
        self.assertEqual(type(context_manager.exception), ValueError)

    def test_separator(self):
        self.assertEqual(bytes_from_hex_string(''), b'')
        self.assertEqual(bytes_from_hex_string('DEADBEEF'), b'\xde\xad\xbe\xef')
        self.assertEqual(bytes_from_hex_string('DE:AD:BE:EF', separator=':'), b'\xde\xad\xbe\xef')


class TestNameToEnumItemName(unittest.TestCase):
    def test_convert_simple_name(self):
        self.assertEqual(name_to_enum_item_name('lower'), 'LOWER')

    def test_convert_multipart_name(self):
        self.assertEqual(name_to_enum_item_name('multiple part'), 'MULTIPLE_PART')
        self.assertEqual(name_to_enum_item_name('aplha 123'), 'APLHA_123')
        self.assertEqual(name_to_enum_item_name('m  u  l  t  i  s  p  a  c  e'), 'M_U_L_T_I_S_P_A_C_E')
        self.assertEqual(name_to_enum_item_name('trailing space  '), 'TRAILING_SPACE')

    def test_convert_i18n_name(self):
        self.assertEqual(name_to_enum_item_name(six.ensure_text('αβγ')), six.ensure_text('ΑΒΓ'))

# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.utils import bytes_from_hex_string, bytes_to_hex_string


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

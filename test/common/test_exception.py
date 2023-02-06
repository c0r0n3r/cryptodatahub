# -*- coding: utf-8 -*-

import unittest

from test.common.classes import EnumIntTest

import six

from cryptodatahub.common.exception import InvalidValue


class TestException(unittest.TestCase):
    def test_str(self):
        with six.assertRaisesRegex(
                self, InvalidValue, '0xa is not a valid str member name value'
        ) as context_manager:
            raise InvalidValue(10, str, 'member name')
        self.assertEqual(context_manager.exception.value, 10)

        with six.assertRaisesRegex(
                self, InvalidValue, '0xa is not a valid str'
        ) as context_manager:
            raise InvalidValue(10, str)
        self.assertEqual(context_manager.exception.value, 10)

        with six.assertRaisesRegex(
                self, InvalidValue, '0xa is not a valid EnumIntTest'
        ) as context_manager:
            raise InvalidValue(EnumIntTest.TEN, EnumIntTest)
        self.assertEqual(context_manager.exception.value, 10)

        with six.assertRaisesRegex(
                self, InvalidValue, '1.0 is not a valid float'
        ) as context_manager:
            raise InvalidValue(1.0, float)
        self.assertEqual(context_manager.exception.value, 1.0)

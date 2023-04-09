# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from test.common.classes import TestClasses

from cryptodatahub.common.parameter import DHParameterNumbers, DHParamWellKnown, DHParamWellKnownParams


class TestDHParamWellKnownParams(unittest.TestCase):
    def test_eq(self):
        self.assertEqual(DHParameterNumbers(1, 2), DHParameterNumbers(1, 2))
        self.assertEqual(DHParameterNumbers(1, 2, None), DHParameterNumbers(1, 2, None))

        self.assertNotEqual(DHParameterNumbers(1, 2, 3), DHParameterNumbers(1, 2, 4))
        self.assertEqual(DHParameterNumbers(1, 2, None), DHParameterNumbers(1, 2, 3))


class TestDHParamWellKnown(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return DHParamWellKnown

    def test_eq(self):
        self.assertEqual(
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, False),
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, False)
        )
        self.assertEqual(
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, False),
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name2', 'source1', 1, False)
        )
        self.assertEqual(
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, False),
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source2', 1, False)
        )
        self.assertEqual(
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, False),
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 2, False)
        )
        self.assertEqual(
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, False),
            DHParamWellKnownParams(DHParameterNumbers(1, 2), 'name1', 'source1', 1, True)
        )

    def test_str(self):
        self.assertEqual(
            str(DHParamWellKnown.RFC2539_768_BIT_MODP_GROUP.value),
            '768-bit MODP Group (RFC2409/RFC2539/Oakley Group 1)'
        )

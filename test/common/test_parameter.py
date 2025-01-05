# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import NamedGroup
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.parameter import DHParameterNumbers, DHParamWellKnown, ECParamWellKnown


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

    def test_from_parameter_numbers(self):
        dh_param = DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP
        self.assertEqual(
            DHParamWellKnown.from_parameter_numbers(dh_param.value.parameter_numbers),
            dh_param
        )

    def test_str(self):
        self.assertEqual(
            str(DHParamWellKnown.RFC2539_768_BIT_MODP_GROUP.value),
            '768-bit MODP Group/Oakley Group 1 (RFC 2409, RFC 2539)'
        )
        self.assertEqual(
            str(DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024.value),
            '1024-bit Apache 2.0.18 builtin DH parameter'
        )


class TestECParamWellKnown(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return ECParamWellKnown

    def test_from_named_group(self):
        self.assertEqual(
           ECParamWellKnown.from_named_group(NamedGroup.PRIME256V1),
           ECParamWellKnown.PRIME256V1
        )

        with self.assertRaisesRegex(
                InvalidValue, "NamedGroup.C2ONB239V4.* is not a valid ECParamWellKnown"
        ) as context_manager:
            ECParamWellKnown.from_named_group(NamedGroup.C2ONB239V4)
        self.assertEqual(context_manager.exception.value, NamedGroup.C2ONB239V4)

    def test_from_parameter_numbers(self):
        ec_param = ECParamWellKnown.PRIME256V1
        self.assertEqual(
           ECParamWellKnown.from_parameter_numbers(ec_param.value.parameter_numbers),
           ec_param
        )

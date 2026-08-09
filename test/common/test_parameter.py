# SPDX-License-Identifier: MPL-2.0

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import NamedGroup
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import AttackNamed, Grade
from cryptodatahub.common.parameter import (
    DHParameterNumbers,
    DHParamWellKnown,
    ECParameterForm,
    ECParameterNumbersWeierstrassPrime,
    ECParamWellKnown,
    ECParamWellKnownParams,
    KeyEncapsulationMechanism,
)


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

    def test_sources(self):
        sources = DHParamWellKnown.RFC2539_768_BIT_MODP_GROUP.value.sources
        self.assertEqual(
            [source.value.name for source in sources], ['RFC 2409', 'RFC 2539', 'IETF']
        )
        self.assertEqual(
            [
                source.value.name
                for source in DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024
                .value.sources
            ],
            ['Apache'],
        )

    def test_non_safe_prime(self):
        group = DHParamWellKnown.RFC5114_1024_BIT_MODP_GROUP_WITH_160_BIT_PRIME_ORDER_SUBGROUP
        self.assertIn(
            AttackNamed.NON_SAFE_PRIME,
            [vulnerability.named for vulnerability in group.value.vulnerabilities],
        )
        self.assertEqual(group.value.min_grade, Grade.DEPRECATED)

    def test_entries_of_one_name_stay_apart(self):
        self.assertEqual(
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_512.value.name,
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024.value.name,
        )
        self.assertNotEqual(
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_512,
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024,
        )


class TestECParamWellKnownParams(unittest.TestCase):
    def test_error_parameter_form_mismatch(self):
        with self.assertRaisesRegex(
                InvalidValue, 'MONTGOMERY.* is not a valid ECParamWellKnownParams parameter_form value'
        ):
            ECParamWellKnownParams(
                name='prime field curve declared as a Montgomery curve',
                long_name=None,
                vulnerabilities=[],
                aliases=[],
                sources=[],
                parameter_form=ECParameterForm.MONTGOMERY,
                parameter_numbers=ECParameterNumbersWeierstrassPrime(
                    p=23, a=1, b=1, x=3, y=10, n=28, h=1, seed=None
                ),
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


class TestKeyEncapsulationMechanism(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return KeyEncapsulationMechanism

    def test_from_named_group(self):
        self.assertEqual(
            KeyEncapsulationMechanism.from_named_group(NamedGroup.ML_KEM_768),
            KeyEncapsulationMechanism.ML_KEM_768
        )

        with self.assertRaisesRegex(
                InvalidValue, "NamedGroup.PRIME256V1.* is not a valid KeyEncapsulationMechanism"
        ) as context_manager:
            KeyEncapsulationMechanism.from_named_group(NamedGroup.PRIME256V1)
        self.assertEqual(context_manager.exception.value, NamedGroup.PRIME256V1)

    def test_named_group_exists(self):
        self.assertEqual([
            key_encapsulation_mechanism.name
            for key_encapsulation_mechanism in KeyEncapsulationMechanism
            if key_encapsulation_mechanism.name not in NamedGroup.__members__
        ], [])

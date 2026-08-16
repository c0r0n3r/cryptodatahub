# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import NamedGroup
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.parameter import ECParamWellKnown
from cryptodatahub.common.pqc import HybridNamedGroup, KeyEncapsulationMechanism


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

    def test_oqs_name(self):
        self.assertEqual(KeyEncapsulationMechanism.MLKEM768.value.oqs_name, 'mlkem768')
        self.assertIsNone(KeyEncapsulationMechanism.ML_KEM_768.value.oqs_name)


class TestHybridNamedGroup(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return HybridNamedGroup

    def test_halves(self):
        self.assertEqual(
            HybridNamedGroup.CECPQ2.value.classical_key_parameter, ECParamWellKnown.CURVE25519
        )
        self.assertEqual(
            HybridNamedGroup.CECPQ2.value.post_quantum_key_parameter,
            KeyEncapsulationMechanism.NTRU_HRSS_701,
        )

    def test_named_group_exists(self):
        self.assertEqual([
            hybrid_named_group.name
            for hybrid_named_group in HybridNamedGroup
            if hybrid_named_group.name not in NamedGroup.__members__
        ], [])

    def test_oqs_name(self):
        self.assertEqual(HybridNamedGroup.X25519_ML_KEM_768.value.oqs_name, 'X25519MLKEM768')
        self.assertEqual(HybridNamedGroup.SECP256R1_FRODO640AES.value.oqs_name, 'p256_frodo640aes')
        self.assertIsNone(HybridNamedGroup.CECPQ2.value.oqs_name)

    def test_every_oqs_name_a_named_group_has_is_carried(self):
        self.assertEqual([
            named_group.name
            for named_group in NamedGroup
            if named_group.value.oqs_name is not None and
            named_group.name in HybridNamedGroup.__members__ and
            HybridNamedGroup[named_group.name].value.oqs_name != named_group.value.oqs_name
        ], [])

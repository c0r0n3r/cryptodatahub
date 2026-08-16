# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import NamedGroup
from cryptodatahub.common.exception import InvalidValue
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


class TestHybridNamedGroup(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return HybridNamedGroup

    def test_halves(self):
        self.assertEqual(HybridNamedGroup.CECPQ2.value.classical_named_group, NamedGroup.CURVE25519)
        self.assertEqual(HybridNamedGroup.CECPQ2.value.post_quantum_named_group, NamedGroup.NTRU_HRSS_701)

    def test_named_group_exists(self):
        self.assertEqual([
            hybrid_named_group.name
            for hybrid_named_group in HybridNamedGroup
            if hybrid_named_group.name not in NamedGroup.__members__
        ], [])

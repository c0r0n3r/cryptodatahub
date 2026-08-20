# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestClasses

from cryptodatahub.common.parameter import ECParamWellKnown
from cryptodatahub.common.pqc import HybridNamedGroup, KeyEncapsulationMechanism


class TestKeyEncapsulationMechanism(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return KeyEncapsulationMechanism

    def test_oqs_name(self):
        self.assertEqual(KeyEncapsulationMechanism.MLKEM768.value.oqs_name, 'mlkem768')
        self.assertIsNone(KeyEncapsulationMechanism.ML_KEM_768.value.oqs_name)

    def test_no_field_size(self):
        self.assertIsNone(KeyEncapsulationMechanism.ML_KEM_768.value.field_size)


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

    def test_oqs_name(self):
        self.assertEqual(HybridNamedGroup.X25519_ML_KEM_768.value.oqs_name, 'X25519MLKEM768')
        self.assertEqual(HybridNamedGroup.SECP256R1_FRODO640AES.value.oqs_name, 'p256_frodo640aes')
        self.assertIsNone(HybridNamedGroup.CECPQ2.value.oqs_name)

    def test_no_field_size(self):
        self.assertIsNone(HybridNamedGroup.X25519_ML_KEM_768.value.field_size)

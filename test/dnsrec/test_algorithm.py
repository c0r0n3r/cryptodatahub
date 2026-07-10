# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import Authentication, Hash

from cryptodatahub.dnsrec.algorithm import SshFpAlgorithm, SshFpFingerprintType


class TestSshFpAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return SshFpAlgorithm

    def test_name(self):
        self.assertEqual(str(SshFpAlgorithm.RSA.value), 'RSA')

    def test_algorithm(self):
        self.assertEqual(SshFpAlgorithm.RSA.value.algorithm, Authentication.RSA)


class TestSshFpFingerprintType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return SshFpFingerprintType

    def test_name(self):
        self.assertEqual(str(SshFpFingerprintType.SHA2_256.value), 'SHA-256')

    def test_hash(self):
        self.assertEqual(SshFpFingerprintType.SHA2_256.value.hash, Hash.SHA2_256)

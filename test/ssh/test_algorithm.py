# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.ssh.algorithm import (
    SshEllipticCurveIdentifier,
    SshEncryptionAlgorithm,
    SshMacAlgorithm,
    SshKexAlgorithm,
    SshHostKeyAlgorithm,
    SshCompressionAlgorithm,
)


class TestSshEncryptionAlgorithm(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return SshEncryptionAlgorithm


class TestSshMacAlgorithm(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return SshMacAlgorithm

    def test_size(self):
        self.assertEqual(SshMacAlgorithm.HMAC_SHA2_256.value.size, 256)
        self.assertEqual(SshMacAlgorithm.HMAC_SHA2_256_96.value.size, 96)


class TestSshKexAlgorithm(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return SshKexAlgorithm


class TestSshHostKeyAlgorithm(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return SshHostKeyAlgorithm


class TestSshCompressionAlgorithm(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return SshCompressionAlgorithm


class TestSshEllipticCurveIdentifier(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return SshEllipticCurveIdentifier

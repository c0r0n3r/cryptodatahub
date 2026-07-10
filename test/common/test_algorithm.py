# SPDX-License-Identifier: MPL-2.0

import unittest

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import (
    Authentication,
    BlockCipher,
    BlockCipherMode,
    Hash,
    KeyExchange,
    NamedGroup,
    MAC,
    MACModeParams,
    MACParams,
    Signature,
)


class TestAuthentication(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Authentication


class TestBlockCipher(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return BlockCipher

    def test_aead(self):
        self.assertFalse(BlockCipher.CHACHA20.value.aead)
        self.assertFalse(BlockCipher.AES_128.value.aead)


class TestBlockCipherMode(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return BlockCipherMode

    def test_aead(self):
        for mode in (BlockCipherMode.GCM, BlockCipherMode.GCM_8,
                     BlockCipherMode.CCM, BlockCipherMode.CCM_8,
                     BlockCipherMode.MGM, BlockCipherMode.GMAC,
                     BlockCipherMode.EAX):
            self.assertTrue(mode.value.aead, msg=mode.name)
        for mode in (BlockCipherMode.CBC, BlockCipherMode.CTR,
                     BlockCipherMode.CFB, BlockCipherMode.OFB,
                     BlockCipherMode.ECB, BlockCipherMode.CNT):
            self.assertFalse(mode.value.aead, msg=mode.name)


class TestHash(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Hash


class TestKeyExchange(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return KeyExchange


class TestNamedGroup(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return NamedGroup


class TestMAC(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return MAC


class TestMACParams(unittest.TestCase):
    def test_error_both_attributes_are_null(self):
        with self.assertRaises(ValueError):
            MACParams('name', 'long_name', None, None, None, None)


class TestMACModeParams(unittest.TestCase):
    def test_gradeable(self):
        self.assertTrue(len(MACModeParams.get_gradeable_name()))


class TestSignature(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Signature

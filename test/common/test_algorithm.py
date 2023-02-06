# -*- coding: utf-8 -*-

try:
    import unittest2 as unittest
except ImportError:
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


class TestBlockCipherMode(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return BlockCipherMode


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
            MACParams('name', 'long_name', None, None, None)


class TestSignature(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Signature

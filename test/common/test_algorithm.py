# -*- coding: utf-8 -*-

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
            MACParams('name', 'long_name', None, None, None, None)


class TestMACModeParams(unittest.TestCase):
    def test_gradeable(self):
        self.assertTrue(len(MACModeParams.get_gradeable_name()))


class TestSignature(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Signature

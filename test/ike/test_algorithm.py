# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.ike.algorithm import (
    Ikev2PayloadType,
    Ikev2NotifyType,
    Ikev2ExtendedSequenceNumber,
    Ikev2TransformType,
    Ikev2AuthenticationMethod,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2EncryptionAlgorithmParams,
    Ikev2HashAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2PseudorandomFunction,
    Ikev1AttributeType,
    Ikev1Doi,
    Ikev1NotifyType,
    Ikev1PayloadType,
    Ikev1ProtocolId,
    Ikev1TransformType,
)


class TestIkev2PseudorandomFunction(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2PseudorandomFunction

    def test_str(self):
        self.assertEqual(str(Ikev2PseudorandomFunction.PRF_HMAC_MD5.value), 'MD5')


class TestIkev2AuthenticationMethod(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2AuthenticationMethod

    def test_str(self):
        self.assertEqual(
            str(Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE.value),
            'RSA Digital Signature'
        )


class TestIkev2DiffieHellmanGroup(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2DiffieHellmanGroup

    def test_str(self):
        self.assertEqual(
            str(Ikev2DiffieHellmanGroup.MODP_GROUP_768_BIT.value),
            '768-bit MODP Group/Oakley Group 1'
        )


class TestIkev2EncryptionAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2EncryptionAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev2EncryptionAlgorithm.ENCR_DES_IV64.value),
            'DES (CBC)'
        )
        self.assertEqual(
            str(Ikev2EncryptionAlgorithmParams(
                code=0,
                bulk_ciphers=[BlockCipher.CHACHA20],
                block_cipher_mode=None,
            )),
            'ChaCha20'
        )
        self.assertEqual(
            str(Ikev2EncryptionAlgorithm.ENCR_NULL.value),
            'null'
        )


class TestIkev2HashAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2HashAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev2HashAlgorithm.HASH_MD5.value),
            'MD5'
        )


class TestIkev2IntegrityAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2IntegrityAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev2IntegrityAlgorithm.AUTH_HMAC_MD5_96.value),
            'MD5'
        )
        self.assertEqual(
            str(Ikev2IntegrityAlgorithm.NONE.value),
            'null'
        )


class TestIkev2PayloadType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2PayloadType


class TestIkev2NotifyType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2NotifyType


class TestIkev2ExtendedSequenceNumber(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2ExtendedSequenceNumber


class TestIkev2TransformType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2TransformType


class TestIkev1AttributeType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1AttributeType


class TestIkev1Doi(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1Doi


class TestIkev1NotifyType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1NotifyType


class TestIkev1PayloadType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1PayloadType


class TestIkev1ProtocolId(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1ProtocolId


class TestIkev1TransformType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1TransformType

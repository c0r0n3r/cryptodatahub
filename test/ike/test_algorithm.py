# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestClasses

from cryptodatahub.ike.version import IkeVersion
from cryptodatahub.ike.algorithm import (
    IkeEncryptionBulkCipherEntry,
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
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1EncryptionAlgorithmParams,
    Ikev1GroupType,
    Ikev1HashAlgorithm,
    Ikev1LifeType,
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
                bulk_ciphers=[{
                    "cipher": "CHACHA20",
                    "names": {"STRONGSWAN": None, "LIBRESWAN": None, "OPENSWAN": None},
                }],
                block_cipher_mode=None,
            )),
            'ChaCha20'
        )
        self.assertEqual(
            str(Ikev2EncryptionAlgorithm.ENCR_NULL.value),
            'null'
        )
        existing_entry = IkeEncryptionBulkCipherEntry(
            cipher='AES_128',
            names={'STRONGSWAN': None, 'LIBRESWAN': None, 'OPENSWAN': None},
        )
        self.assertEqual(
            str(Ikev2EncryptionAlgorithmParams(
                code=0,
                bulk_ciphers=[existing_entry],
                block_cipher_mode=None,
            )),
            'AES-128'
        )

    def test_aead_via_block_cipher_mode(self):
        # AEAD algorithms: mode carries aead=True, propagated to encr.aead
        self.assertTrue(Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16.value.aead)
        self.assertTrue(Ikev2EncryptionAlgorithm.ENCR_AES_CCM_8.value.aead)
        self.assertTrue(Ikev2EncryptionAlgorithm.ENCR_NULL_AUTH_AES_GMAC.value.aead)
        self.assertTrue(Ikev2EncryptionAlgorithm.ENCR_KUZNYECHIK_MGM_KTREE.value.aead)
        self.assertTrue(Ikev2EncryptionAlgorithm.ENCR_KUZNYECHIK_MGM_MAC_KTREE.value.aead)
        # Non-AEAD algorithms: mode carries aead=False
        self.assertFalse(Ikev2EncryptionAlgorithm.ENCR_AES_CBC.value.aead)
        self.assertFalse(Ikev2EncryptionAlgorithm.ENCR_AES_CTR.value.aead)
        # ChaCha20-Poly1305: stream cipher, no block_cipher_mode; AEAD via bulk cipher
        chacha = Ikev2EncryptionAlgorithm.ENCR_CHACHA20_POLY1305.value
        self.assertIsNone(chacha.block_cipher_mode)
        self.assertTrue(chacha.aead)


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


class TestIkev1LifeType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1LifeType


class TestIkev1GroupType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1GroupType


class TestIkev1AuthenticationMethod(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1AuthenticationMethod


class TestIkev1DiffieHellmanGroup(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1DiffieHellmanGroup

    def test_str(self):
        self.assertEqual(
            str(Ikev1DiffieHellmanGroup.MODP_768_BIT.value),
            '768-bit MODP Group/Oakley Group 1'
        )


class TestIkev1EncryptionAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1EncryptionAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev1EncryptionAlgorithm.DES_CBC.value),
            'DES (CBC)'
        )
        self.assertEqual(
            str(Ikev1EncryptionAlgorithmParams(
                code=0,
                bulk_ciphers=[],
                block_cipher_mode=None,
            )),
            'null'
        )
        self.assertEqual(
            str(Ikev1EncryptionAlgorithmParams(
                code=0,
                bulk_ciphers=[{
                    "cipher": "AES_128",
                    "names": {"STRONGSWAN": None, "LIBRESWAN": None, "OPENSWAN": None},
                }],
                block_cipher_mode=None,
            )),
            'AES-128'
        )


class TestIkev1HashAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1HashAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev1HashAlgorithm.MD5.value),
            'MD5'
        )


class TestIkeVersion(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return IkeVersion

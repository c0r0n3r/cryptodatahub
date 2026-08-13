# SPDX-License-Identifier: MPL-2.0

import unittest

from test.common.classes import TestClasses

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.exception import InvalidProposalToken, InvalidValue
from cryptodatahub.ike.version import IkeVersion
from cryptodatahub.ike.algorithm import (
    IkeEncryptionBulkCipherEntry,
    IkeLongNameParams,
    IkeVendorId,
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
    Ikev1CertificateType,
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

    def test_from_name(self):
        for pseudorandom_function in Ikev2PseudorandomFunction:
            self.assertEqual(
                Ikev2PseudorandomFunction.from_name(pseudorandom_function.name.lower()),
                pseudorandom_function
            )
        with self.assertRaises(InvalidValue):
            Ikev2PseudorandomFunction.from_name('no-such-name')

    def test_from_implementation_name(self):
        for pseudorandom_function in Ikev2PseudorandomFunction:
            for entity, token in pseudorandom_function.value.names.items():
                if token is not None:
                    self.assertEqual(
                        Ikev2PseudorandomFunction.from_implementation_name(entity, token),
                        pseudorandom_function
                    )
        with self.assertRaises(InvalidValue):
            Ikev2PseudorandomFunction.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')


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

    def test_from_name(self):
        for diffie_hellman_group in Ikev2DiffieHellmanGroup:
            self.assertEqual(
                Ikev2DiffieHellmanGroup.from_name(diffie_hellman_group.name.lower()),
                diffie_hellman_group
            )
        with self.assertRaises(InvalidValue):
            Ikev2DiffieHellmanGroup.from_name('no-such-name')

    def test_from_implementation_name(self):
        for diffie_hellman_group in Ikev2DiffieHellmanGroup:
            for entity, token in diffie_hellman_group.value.names.items():
                if token is not None:
                    self.assertEqual(
                        Ikev2DiffieHellmanGroup.from_implementation_name(entity, token),
                        diffie_hellman_group
                    )
        with self.assertRaises(InvalidValue):
            Ikev2DiffieHellmanGroup.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')


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

    def test_from_name(self):
        for encryption_algorithm in Ikev2EncryptionAlgorithm:
            self.assertEqual(
                Ikev2EncryptionAlgorithm.from_name(encryption_algorithm.name.lower()),
                encryption_algorithm
            )
        with self.assertRaises(InvalidValue):
            Ikev2EncryptionAlgorithm.from_name('no-such-name')

    def test_from_implementation_name(self):
        for encryption_algorithm in Ikev2EncryptionAlgorithm:
            for bulk_cipher in encryption_algorithm.value.bulk_ciphers:
                for entity, token in bulk_cipher.names.items():
                    if token is not None:
                        self.assertEqual(
                            Ikev2EncryptionAlgorithm.from_implementation_name(entity, token),
                            (encryption_algorithm, bulk_cipher.cipher.value.key_size)
                        )
        with self.assertRaises(InvalidValue):
            Ikev2EncryptionAlgorithm.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')

    def test_from_proposal_token(self):
        self.assertEqual(
            Ikev2EncryptionAlgorithm.from_proposal_token(Entity.STRONGSWAN, 'aes256gcm16'),
            (Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 256)
        )
        self.assertEqual(
            Ikev2EncryptionAlgorithm.from_proposal_token(None, 'encr_aes_cbc/128'),
            (Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)
        )
        self.assertEqual(
            Ikev2EncryptionAlgorithm.from_proposal_token(None, 'encr_chacha20_poly1305'),
            (Ikev2EncryptionAlgorithm.ENCR_CHACHA20_POLY1305, 256)
        )

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev2EncryptionAlgorithm.from_proposal_token(Entity.STRONGSWAN, 'no-such-cipher')
        self.assertEqual(context_manager.exception.hint, 'unknown strongswan token')

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev2EncryptionAlgorithm.from_proposal_token(None, 'encr_null')
        self.assertEqual(context_manager.exception.hint, 'encryption algorithm has no offerable key length')


class TestIkev2HashAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2HashAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev2HashAlgorithm.SHA2_256.value),
            'SHA-256'
        )

    def test_str_identity(self):
        self.assertIsNone(Ikev2HashAlgorithm.IDENTITY.value.hash_algorithm)
        self.assertEqual(
            str(Ikev2HashAlgorithm.IDENTITY.value),
            'Identity'
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

    def test_from_name(self):
        for integrity_algorithm in Ikev2IntegrityAlgorithm:
            self.assertEqual(
                Ikev2IntegrityAlgorithm.from_name(integrity_algorithm.name.lower()),
                integrity_algorithm
            )
        with self.assertRaises(InvalidValue):
            Ikev2IntegrityAlgorithm.from_name('no-such-name')

    def test_from_implementation_name(self):
        for integrity_algorithm in Ikev2IntegrityAlgorithm:
            for entity, token in integrity_algorithm.value.names.items():
                if token is not None:
                    self.assertEqual(
                        Ikev2IntegrityAlgorithm.from_implementation_name(entity, token),
                        integrity_algorithm
                    )
        with self.assertRaises(InvalidValue):
            Ikev2IntegrityAlgorithm.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')


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


class TestIkeLongNameParams(unittest.TestCase):
    def test_str_returns_long_name(self):
        class _ConcreteLongName(IkeLongNameParams):
            @classmethod
            def get_code_size(cls):
                return 1

        entry = _ConcreteLongName(code=1, long_name='human readable')
        self.assertEqual(str(entry), 'human readable')


class TestIkev1CertificateType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1CertificateType

    def test_str(self):
        self.assertEqual(
            str(Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE.value),
            'X.509 Certificate - Signature',
        )


class TestIkev1AuthenticationMethod(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1AuthenticationMethod

    def test_str(self):
        self.assertEqual(
            str(Ikev1AuthenticationMethod.RSA_SIGNATURES.value),
            'RSA Signatures',
        )

    def test_from_name(self):
        for authentication_method in Ikev1AuthenticationMethod:
            self.assertEqual(
                Ikev1AuthenticationMethod.from_name(authentication_method.name.lower()),
                authentication_method
            )
        with self.assertRaises(InvalidValue):
            Ikev1AuthenticationMethod.from_name('no-such-name')

    def test_from_implementation_name(self):
        for authentication_method in Ikev1AuthenticationMethod:
            for entity, token in authentication_method.value.names.items():
                if token is not None:
                    self.assertEqual(
                        Ikev1AuthenticationMethod.from_implementation_name(entity, token),
                        authentication_method
                    )
        self.assertEqual(
            Ikev1AuthenticationMethod.from_implementation_name(Entity.STRONGSWAN, 'psk'),
            Ikev1AuthenticationMethod.PRE_SHARED_KEY
        )
        with self.assertRaises(InvalidValue):
            Ikev1AuthenticationMethod.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')
        with self.assertRaises(InvalidValue):
            Ikev1AuthenticationMethod.from_implementation_name(Entity.STRONGSWAN, None)


class TestIkev1DiffieHellmanGroup(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1DiffieHellmanGroup

    def test_str(self):
        self.assertEqual(
            str(Ikev1DiffieHellmanGroup.MODP_768_BIT.value),
            '768-bit MODP Group/Oakley Group 1'
        )

    def test_from_name(self):
        for diffie_hellman_group in Ikev1DiffieHellmanGroup:
            self.assertEqual(
                Ikev1DiffieHellmanGroup.from_name(diffie_hellman_group.name.lower()),
                diffie_hellman_group
            )
        with self.assertRaises(InvalidValue):
            Ikev1DiffieHellmanGroup.from_name('no-such-name')

    def test_from_implementation_name(self):
        for diffie_hellman_group in Ikev1DiffieHellmanGroup:
            for entity, token in diffie_hellman_group.value.names.items():
                if token is not None:
                    self.assertEqual(
                        Ikev1DiffieHellmanGroup.from_implementation_name(entity, token),
                        diffie_hellman_group
                    )
        with self.assertRaises(InvalidValue):
            Ikev1DiffieHellmanGroup.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')


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

    def test_from_name(self):
        for encryption_algorithm in Ikev1EncryptionAlgorithm:
            self.assertEqual(
                Ikev1EncryptionAlgorithm.from_name(encryption_algorithm.name.lower()),
                encryption_algorithm
            )
        with self.assertRaises(InvalidValue):
            Ikev1EncryptionAlgorithm.from_name('no-such-name')

    def test_from_implementation_name(self):
        for encryption_algorithm in Ikev1EncryptionAlgorithm:
            for bulk_cipher in encryption_algorithm.value.bulk_ciphers:
                for entity, token in bulk_cipher.names.items():
                    if token is not None:
                        self.assertEqual(
                            Ikev1EncryptionAlgorithm.from_implementation_name(entity, token),
                            (encryption_algorithm, bulk_cipher.cipher.value.key_size)
                        )
        with self.assertRaises(InvalidValue):
            Ikev1EncryptionAlgorithm.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')

    def test_from_proposal_token(self):
        self.assertEqual(
            Ikev1EncryptionAlgorithm.from_proposal_token(Entity.STRONGSWAN, 'aes256'),
            (Ikev1EncryptionAlgorithm.AES_CBC, 256)
        )
        self.assertEqual(
            Ikev1EncryptionAlgorithm.from_proposal_token(Entity.LIBRESWAN, 'aes_gcm_c256'),
            (Ikev1EncryptionAlgorithm.AES_GCM_16, 256)
        )
        self.assertEqual(
            Ikev1EncryptionAlgorithm.from_proposal_token(None, 'aes_cbc/128'),
            (Ikev1EncryptionAlgorithm.AES_CBC, 128)
        )
        self.assertEqual(
            Ikev1EncryptionAlgorithm.from_proposal_token(None, 'des_cbc'),
            (Ikev1EncryptionAlgorithm.DES_CBC, 56)
        )

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev1EncryptionAlgorithm.from_proposal_token(None, 'no_such_cipher/128')
        self.assertEqual(context_manager.exception.hint, 'unknown iana token')

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev1EncryptionAlgorithm.from_proposal_token(None, 'aes_cbc')
        self.assertEqual(
            context_manager.exception.hint, 'key length is required on a variable-key encryption algorithm'
        )

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev1EncryptionAlgorithm.from_proposal_token(None, 'des_cbc/56')
        self.assertEqual(
            context_manager.exception.hint, 'key length is forbidden on a fixed-key encryption algorithm'
        )

        for key_length_text in ('64', 'notanumber'):
            with self.assertRaises(InvalidProposalToken) as context_manager:
                Ikev1EncryptionAlgorithm.from_proposal_token(None, f'aes_cbc/{key_length_text}')
            self.assertIn('key length must be one of', context_manager.exception.hint)


class TestIkev1HashAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev1HashAlgorithm

    def test_str(self):
        self.assertEqual(
            str(Ikev1HashAlgorithm.MD5.value),
            'MD5'
        )

    def test_from_name(self):
        for hash_algorithm in Ikev1HashAlgorithm:
            self.assertEqual(
                Ikev1HashAlgorithm.from_name(hash_algorithm.name.lower()),
                hash_algorithm
            )
        with self.assertRaises(InvalidValue):
            Ikev1HashAlgorithm.from_name('no-such-name')

    def test_from_implementation_name(self):
        for hash_algorithm in Ikev1HashAlgorithm:
            for entity, token in hash_algorithm.value.names.items():
                if token is not None:
                    self.assertEqual(
                        Ikev1HashAlgorithm.from_implementation_name(entity, token),
                        hash_algorithm
                    )
        with self.assertRaises(InvalidValue):
            Ikev1HashAlgorithm.from_implementation_name(Entity.STRONGSWAN, 'no-such-token')

    def test_from_proposal_token(self):
        self.assertEqual(
            Ikev1HashAlgorithm.from_proposal_token(Entity.STRONGSWAN, 'sha256'),
            Ikev1HashAlgorithm.SHA2_256
        )
        self.assertEqual(
            Ikev1HashAlgorithm.from_proposal_token(None, 'sha2_256'),
            Ikev1HashAlgorithm.SHA2_256
        )

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev1HashAlgorithm.from_proposal_token(Entity.STRONGSWAN, 'no-such-hash')
        self.assertEqual(context_manager.exception.hint, 'unknown strongswan token')

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev1HashAlgorithm.from_proposal_token(None, 'no-such-hash')
        self.assertEqual(context_manager.exception.hint, 'unknown iana token')

        with self.assertRaises(InvalidProposalToken) as context_manager:
            Ikev1HashAlgorithm.from_proposal_token(None, 'sha2_256/128')
        self.assertEqual(context_manager.exception.hint, 'key length is forbidden on a non-encryption algorithm')


class TestIkeVendorId(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return IkeVendorId

    def test_from_binary(self):
        self.assertEqual(
            IkeVendorId.from_binary(bytes.fromhex('fbf47614984031fa8e3bb6198089b223')),
            IkeVendorId.SSH_IPSEC_EXPRESS_1_1_0,
        )
        self.assertEqual(
            IkeVendorId.from_binary(bytearray.fromhex('fbf47614984031fa8e3bb6198089b223')),
            IkeVendorId.SSH_IPSEC_EXPRESS_1_1_0,
        )

    def test_from_binary_unknown(self):
        with self.assertRaises(InvalidValue):
            IkeVendorId.from_binary(b'\x00\x01\x02\x03')

    def test_str(self):
        self.assertEqual(
            str(IkeVendorId.SSH_IPSEC_EXPRESS_1_1_0.value),
            'SSH Communications Security IPSEC Express version 1.1.0',
        )
        self.assertEqual(
            str(IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_02N.value),
            'draft-ietf-ipsec-nat-t-ike-02\\n',
        )


class TestIkeVersion(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return IkeVersion

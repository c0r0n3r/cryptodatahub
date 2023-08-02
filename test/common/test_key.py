# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

import collections
import datetime
import os

from test.common.classes import TestClasses

import asn1crypto

from cryptodatahub.common.algorithm import Authentication, Hash, Signature
from cryptodatahub.common.key import PublicKey, PublicKeyX509Base
from cryptodatahub.common.utils import bytes_from_hex_string

from cryptodatahub.tls.algorithm import TlsExtensionType


class TestPublicKey(TestClasses.TestKeyBase):
    def test_pem(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(public_key.pem, self._get_public_key_pem('snakeoil_cert_pubkey'))

    def test_der(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(public_key, PublicKey.from_der(public_key.der))

    def test_digest(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(
            PublicKey.get_digest(Hash.MD5, public_key.der),
            bytes_from_hex_string('5D:B2:D9:9F:97:5C:C6:19:B3:91:7E:F8:1A:37:2C:78', ':')
        )

        with self.assertRaises(NotImplementedError) as context_manager:
            PublicKey.get_digest(Hash.SHA2_512, public_key.der)
        self.assertEqual(context_manager.exception.args, (Hash.SHA2_512, ))

    def test_fingerprints(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(
            public_key.fingerprints,
            {
                Hash.MD5:
                    '5D:B2:D9:9F:97:5C:C6:19:B3:91:7E:F8:1A:37:2C:78',
                Hash.SHA1:
                    '49:4A:82:89:7C:62:18:44:CF:02:A9:74:E9:57:CD:FC:A2:A4:45:9B',
                Hash.SHA2_256:
                    '29:D4:FC:11:59:74:C3:47:25:25:E7:11:77:44:7C:7A:' +
                    'D3:68:A0:79:70:E5:2D:58:1E:54:7A:60:F9:EA:AF:F4',
            }
        )

    def test_key_type(self):
        public_key_x509 = self._get_public_key_x509('ecc256.badssl.com')
        self.assertEqual(public_key_x509.key_type, Authentication.ECDSA)
        public_key_x509 = self._get_public_key_x509('ecc384.badssl.com')
        self.assertEqual(public_key_x509.key_type, Authentication.ECDSA)

        public_key_x509 = self._get_public_key_x509('rsa2048.badssl.com')
        self.assertEqual(public_key_x509.key_type, Authentication.RSA)
        public_key_x509 = self._get_public_key_x509('rsa4096.badssl.com')
        self.assertEqual(public_key_x509.key_type, Authentication.RSA)
        public_key_x509 = self._get_public_key_x509('rsa8192.badssl.com')
        self.assertEqual(public_key_x509.key_type, Authentication.RSA)

    def test_key_size(self):
        public_key_x509 = self._get_public_key_x509('ecc256.badssl.com')
        self.assertEqual(public_key_x509.key_size, 256)
        public_key_x509 = self._get_public_key_x509('ecc384.badssl.com')
        self.assertEqual(public_key_x509.key_size, 384)

        public_key_x509 = self._get_public_key_x509('rsa2048.badssl.com')
        self.assertEqual(public_key_x509.key_size, 2048)
        public_key_x509 = self._get_public_key_x509('rsa4096.badssl.com')
        self.assertEqual(public_key_x509.key_size, 4096)
        public_key_x509 = self._get_public_key_x509('rsa8192.badssl.com')
        self.assertEqual(public_key_x509.key_size, 8192)

        self.assertEqual(self._get_public_key_x509('gost_2001_cert').key_size, 256)
        self.assertEqual(self._get_public_key_x509('gost_2012_256_cert').key_size, 256)
        self.assertEqual(self._get_public_key_x509('gost_2012_512_cert').key_size, 512)


class TestPublicKeyX509(TestClasses.TestKeyBase):  # pylint: disable=too-many-public-methods
    def test_eq(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(public_key_x509, public_key_x509)

        self.assertNotEqual(public_key_x509, self._get_public_key_x509('no-common-name.badssl.com'))

        public_key_x509 = self._get_public_key_x509('snakeoil_cert')
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(public_key_x509.public_key, public_key)

    def test_pem_lines(self):
        self.assertEqual(
            PublicKeyX509Base.from_pem_lines(self._get_public_key_pem('expired.badssl.com').split(os.linesep)),
            self._get_public_key_x509('expired.badssl.com')
        )

    def test_pem(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(public_key_x509.pem, self._get_public_key_pem('expired.badssl.com'))

    def test_der(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(public_key_x509, PublicKeyX509Base.from_der(public_key_x509.der))

    def test_digest(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(
            PublicKeyX509Base.get_digest(Hash.MD5, public_key_x509.der),
            bytes_from_hex_string('67:34:4E:61:C0:43:1C:F1:F7:25:7C:1D:6D:E7:A7:85', ':')
        )

    def test_fingerprints(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(
            public_key_x509.fingerprints,
            {
                Hash.MD5:
                    '67:34:4E:61:C0:43:1C:F1:F7:25:7C:1D:6D:E7:A7:85',
                Hash.SHA1:
                    '40:4B:BD:2F:1F:4C:C2:FD:EE:F1:3A:AB:DD:52:3E:F6:1F:1C:71:F3',
                Hash.SHA2_256:
                    'BA:10:5C:E0:2B:AC:76:88:8E:CE:E4:7C:D4:EB:79:41:' +
                    '65:3E:9A:C9:93:B6:1B:2E:B3:DC:C8:20:14:D2:1B:4F',
            }
        )

    def test_common_name(self):
        public_key_x509 = self._get_public_key_x509('no-common-name.badssl.com')
        self.assertNotEqual(public_key_x509.subject, collections.OrderedDict([]))
        self.assertEqual(public_key_x509.subject_alternative_names, ['no-common-name.badssl.com', ])
        self.assertEqual(public_key_x509.valid_domains, ['no-common-name.badssl.com', ])

    def test_subject_alternative_names(self):
        public_key_x509 = self._get_public_key_x509('no-subject.badssl.com')
        self.assertEqual(public_key_x509.subject, collections.OrderedDict([]))
        self.assertEqual(public_key_x509.subject_alternative_names, ['no-subject.badssl.com'])
        self.assertEqual(public_key_x509.valid_domains, ['no-subject.badssl.com'])

        public_key_x509 = self._get_public_key_x509('badssl.com')
        self.assertNotEqual(public_key_x509.subject, collections.OrderedDict([]))
        self.assertEqual(public_key_x509.subject_alternative_names, ['*.badssl.com', 'badssl.com'])
        self.assertEqual(public_key_x509.valid_domains, ['*.badssl.com', 'badssl.com'])

        public_key_x509 = self._get_public_key_x509('gost_2001_cert')
        self.assertNotEqual(public_key_x509.subject, collections.OrderedDict([]))
        self.assertEqual(public_key_x509.subject_alternative_names, [])

    def test_no_subject(self):
        public_key_x509 = self._get_public_key_x509('no-subject.badssl.com')
        self.assertEqual(public_key_x509.subject_alternative_names, ['no-subject.badssl.com', ])
        self.assertEqual(public_key_x509.valid_domains, ['no-subject.badssl.com', ])

    def test_issuer(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(
            public_key_x509.issuer,
            collections.OrderedDict([
                ('country_name', 'GB'),
                ('state_or_province_name', 'Greater Manchester'),
                ('locality_name', 'Salford'),
                ('organization_name', 'COMODO CA Limited'),
                ('common_name', 'COMODO RSA Domain Validation Secure Server CA')
            ])
        )

    def test_crl_distribution_points(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(
            public_key_x509.crl_distribution_points,
            ['http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl']
        )

        public_key_x509 = self._get_public_key_x509('letsencrypt.org')
        self.assertEqual(
            public_key_x509.crl_distribution_points,
            []
        )

    def test_crl_distribution_points_relative_name(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(
            public_key_x509.crl_distribution_points,
            ['http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl', ]
        )

    def test_ocsp_responders(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(public_key_x509.ocsp_responders, ['http://ocsp.comodoca.com'])

    @mock.patch.object(
        asn1crypto.x509.Certificate, 'authority_information_access_value',
        return_value=None
    )
    def test_ocsp_responders_no_extension(self, _):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(public_key_x509.ocsp_responders, [])

    def test_is_ca(self):
        public_key_x509 = self._get_public_key_x509('letsencrypt_isrg_root_x1')
        self.assertTrue(public_key_x509.is_ca)

        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertFalse(public_key_x509.is_ca)

    def test_self_signed(self):
        public_key_x509 = self._get_public_key_x509('letsencrypt_isrg_root_x1')
        self.assertTrue(public_key_x509.is_self_signed)

        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertFalse(public_key_x509.is_self_signed)

    def test_validity(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertTrue(public_key_x509.expired)
        self.assertEqual(
            public_key_x509.valid_not_before,
            datetime.datetime(2015, 4, 9, 0, 0, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(
            public_key_x509.valid_not_after,
            datetime.datetime(2015, 4, 12, 23, 59, 59, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(
            public_key_x509.validity_period,
            datetime.timedelta(days=4, seconds=-1)
        )
        self.assertEqual(
            public_key_x509.validity_remaining_time,
            None
        )

        public_key_x509 = self._get_public_key_x509('badssl.com')
        self.assertFalse(public_key_x509.expired)

    def test_public_key_pin(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertEqual(
            public_key_x509.public_key_pin,
            '9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8='
        )

    def test_extended_validation(self):
        public_key_x509 = self._get_public_key_x509('extended-validation.badssl.com')
        self.assertTrue(public_key_x509.extended_validation)

        public_key_x509 = self._get_public_key_x509('badssl.com')
        self.assertFalse(public_key_x509.extended_validation)

        with mock.patch(
            'asn1crypto.x509.Certificate.certificate_policies_value',
            new_callable=mock.PropertyMock
        ) as prop_mock:
            prop_mock.return_value = None
            self.assertFalse(public_key_x509.extended_validation)

    def test_tls_features(self):
        public_key_x509 = self._get_public_key_x509('badssl.com')
        self.assertEqual(public_key_x509.tls_features, [])

        public_key_x509 = self._get_public_key_x509('bitnami.com')
        self.assertEqual(public_key_x509.tls_features, [TlsExtensionType.STATUS_REQUEST])

    def test_signature_algorithm_unknown(self):
        public_key_x509 = self._get_public_key_x509('sha1-intermediate.badssl.com')
        with mock.patch('asn1crypto.algos.SignedDigestAlgorithmId.dotted', new_callable=mock.PropertyMock) as prop_mock:
            prop_mock.side_effect = KeyError('1.2.840.113549.1.1.2')
            self.assertEqual(
                public_key_x509.signature_hash_algorithm,
                Signature.RSA_WITH_MD2
            )

    def test_signature_algorithm(self):
        public_key_x509 = self._get_public_key_x509('comodo_ssl_ca_sha1')
        self.assertEqual(
            public_key_x509.signature_hash_algorithm,
            Signature.RSA_WITH_SHA1
        )

        public_key_x509 = self._get_public_key_x509('sha256.badssl.com')
        self.assertEqual(
            public_key_x509.signature_hash_algorithm,
            Signature.RSA_WITH_SHA2_256
        )
        public_key_x509 = self._get_public_key_x509('sha384.badssl.com')
        self.assertEqual(
            public_key_x509.signature_hash_algorithm,
            Signature.RSA_WITH_SHA2_384
        )
        public_key_x509 = self._get_public_key_x509('sha512.badssl.com')
        self.assertEqual(public_key_x509.signature_hash_algorithm, Signature.RSA_WITH_SHA2_512)

    def test_subject_match(self):
        public_key_x509 = self._get_public_key_x509('expired.badssl.com')
        self.assertTrue(public_key_x509.is_subject_matches('expired.badssl.com'))
        self.assertTrue(public_key_x509.is_subject_matches('whatever.badssl.com'))
        self.assertFalse(public_key_x509.is_subject_matches('what.ever.badssl.com'))

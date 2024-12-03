# -*- coding: utf-8 -*-

import collections
import datetime
import os
import unittest
from unittest import mock

from test.common.classes import TestClasses

import asn1crypto

from cryptodatahub.common.algorithm import Authentication, Hash, KeyExchange, NamedGroup, Signature
from cryptodatahub.common.key import (
    _PublicKeySizeGradeable,
    PublicKey,
    PublicKeyParamsDsa,
    PublicKeyParamsEddsa,
    PublicKeyParamsEcdsa,
    PublicKeyParamsRsa,
    PublicKeySize,
    PublicKeyX509Base,
    convert_public_key_size,
)
from cryptodatahub.common.grade import AttackNamed, AttackType, Grade, Vulnerability
from cryptodatahub.common.utils import bytes_from_hex_string

from cryptodatahub.tls.algorithm import TlsExtensionType


class TestPublicKeyConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = '1234'
        converted_value = convert_public_key_size(KeyExchange.DHE)(original_value)
        self.assertEqual(id(original_value), id(convert_public_key_size(KeyExchange.DHE)(converted_value)))

    def test_error_invalid_value(self):
        original_value = -1
        converted_value = convert_public_key_size(KeyExchange.DHE)(original_value)
        self.assertEqual(id(converted_value), id(convert_public_key_size(KeyExchange.DHE)(converted_value)))

    def test_none(self):
        converted_value = convert_public_key_size(KeyExchange.DHE)(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        original_value = 2048
        converted_value = convert_public_key_size(KeyExchange.DHE)(original_value)

        self.assertEqual(converted_value, PublicKeySize(KeyExchange.DHE, 2048))

    def test_repr(self):
        self.assertEqual(repr(convert_public_key_size(KeyExchange.DHE)), '<public key size converter>')


class TestPublicKeySizeGradeable(unittest.TestCase):
    def test_gradeable(self):
        self.assertTrue(len(_PublicKeySizeGradeable.get_gradeable_name()))


class TestPublicKeySize(unittest.TestCase):
    @staticmethod
    def _get_vulnerability_values(key_type, key_size):
        return list(PublicKeySize(key_type, key_size).gradeables)

    def test_vulnerabilities(self):
        vulnerability_integer_factorization_weak = Vulnerability(
            attack_type=AttackType.INTEGER_FACTORIZATION,
            grade=Grade.WEAK,
            named=None
        )
        vulnerability_discrete_logarithm_insecure = Vulnerability(
            attack_type=AttackType.DISCRETE_LOGARITHM,
            grade=Grade.INSECURE,
            named=None
        )
        vulnerability_discrete_logarithm_weak = Vulnerability(
            attack_type=AttackType.DISCRETE_LOGARITHM,
            grade=Grade.WEAK,
            named=None
        )
        vulnerability_dheat = Vulnerability(
            attack_type=AttackType.DOS_ATTACK,
            grade=Grade.WEAK,
            named=AttackNamed.DHEAT_ATTACK
        )

        self.assertEqual(PublicKeySize(Authentication.RSA, 2048).gradeables, [_PublicKeySizeGradeable([])])
        self.assertEqual(
            self._get_vulnerability_values(Authentication.RSA, 1024),
            [_PublicKeySizeGradeable([vulnerability_integer_factorization_weak])]
        )
        self.assertEqual(
            self._get_vulnerability_values(Authentication.RSA, 768), [_PublicKeySizeGradeable([Vulnerability(
                attack_type=AttackType.INTEGER_FACTORIZATION,
                grade=Grade.INSECURE,
                named=AttackNamed.FREAK
            )])]
        )

        self.assertEqual(PublicKeySize(Authentication.DSS, 2048).gradeables, [_PublicKeySizeGradeable([])])
        self.assertEqual(
            self._get_vulnerability_values(Authentication.DSS, 1024),
            [_PublicKeySizeGradeable([vulnerability_integer_factorization_weak])]
        )
        self.assertEqual(
            self._get_vulnerability_values(Authentication.DSS, 768), [_PublicKeySizeGradeable([Vulnerability(
                attack_type=AttackType.INTEGER_FACTORIZATION,
                grade=Grade.INSECURE,
                named=None
            )])]

        )

        self.assertEqual(PublicKeySize(KeyExchange.DHE, 2048).gradeables, [_PublicKeySizeGradeable([])])
        self.assertEqual(
            self._get_vulnerability_values(KeyExchange.DHE, 1024),
            [_PublicKeySizeGradeable([vulnerability_integer_factorization_weak])]
        )
        self.assertEqual(
            self._get_vulnerability_values(KeyExchange.DHE, 768), [_PublicKeySizeGradeable([Vulnerability(
                attack_type=AttackType.INTEGER_FACTORIZATION,
                grade=Grade.INSECURE,
                named=AttackNamed.WEAK_DH
            )])]
        )
        self.assertEqual(
            self._get_vulnerability_values(KeyExchange.DHE, 6144),
            [_PublicKeySizeGradeable([vulnerability_dheat])]
        )

        self.assertEqual(PublicKeySize(Authentication.ECDSA, 256).gradeables, [_PublicKeySizeGradeable([])])
        self.assertEqual(
            self._get_vulnerability_values(Authentication.ECDSA, 160),
            [_PublicKeySizeGradeable([vulnerability_discrete_logarithm_weak])]
        )
        self.assertEqual(
            self._get_vulnerability_values(Authentication.ECDSA, 112),
            [_PublicKeySizeGradeable([vulnerability_discrete_logarithm_insecure])]
        )

        self.assertEqual(PublicKeySize(Authentication.EDDSA, 256).gradeables, [_PublicKeySizeGradeable([])])
        self.assertEqual(
            self._get_vulnerability_values(Authentication.EDDSA, 160),
            [_PublicKeySizeGradeable([vulnerability_discrete_logarithm_weak])]
        )
        self.assertEqual(
            self._get_vulnerability_values(Authentication.EDDSA, 112),
            [_PublicKeySizeGradeable([vulnerability_discrete_logarithm_insecure])]
        )

        self.assertEqual(PublicKeySize(Authentication.PSK, 2048).gradeables, None)

    def test_str(self):
        self.assertEqual(str(PublicKeySize(Authentication.RSA, 1024)), '1024')
        self.assertEqual(str(PublicKeySize(Authentication.EDDSA, 256)), '256')


class TestPublicKeyParamsEcdsa(TestClasses.TestKeyBase):
    def test_from_octet_bit_string(self):
        public_key = self._get_public_key('gitlab.com_ssh_ecdsa_key')
        public_key_params = public_key.params

        self.assertEqual(
            public_key_params,
            PublicKeyParamsEcdsa.from_octet_bit_string(
                public_key_params.named_group,
                public_key_params.octet_bit_string,
            )
        )


class TestPublicKey(TestClasses.TestKeyBase):
    def test_from_params(self):
        public_key = self._get_public_key('gitlab.com_ssh_dsa_key')
        public_key_params = public_key.params
        params = PublicKeyParamsDsa(
            prime=public_key_params.prime,
            generator=public_key_params.generator,
            order=public_key_params.order,
            public_key_value=public_key_params.public_key_value,
        )
        public_key = PublicKey.from_params(params)
        self.assertEqual(params, public_key.params)
        self.assertEqual(public_key.key_size, 1024)

        public_key = self._get_public_key('gitlab.com_ssh_ecdsa_key')
        public_key_params = public_key.params
        params = PublicKeyParamsEcdsa(
            named_group=NamedGroup.PRIME256V1,
            point_x=public_key_params.point_x,
            point_y=public_key_params.point_y,
        )
        public_key = PublicKey.from_params(params)
        self.assertEqual(params, public_key.params)
        self.assertEqual(public_key.key_size, 256)

        public_key = self._get_public_key('gitlab.com_ssh_eddsa_key')
        public_key_params = public_key.params
        params = PublicKeyParamsEddsa(
            curve_type=public_key_params.curve_type,
            key_data=public_key_params.key_data,
        )
        public_key = PublicKey.from_params(params)
        self.assertEqual(params, public_key.params)
        self.assertEqual(public_key.key_size, 256)

        public_key = self._get_public_key('ssh_ed448_key')
        public_key_params = public_key.params
        params = PublicKeyParamsEddsa(
            curve_type=public_key_params.curve_type,
            key_data=public_key_params.key_data,
        )
        public_key = PublicKey.from_params(params)
        self.assertEqual(params, public_key.params)
        self.assertEqual(public_key.key_size, 448)

        public_key = self._get_public_key('gitlab.com_ssh_rsa_key')
        public_key_params = public_key.params
        params = PublicKeyParamsRsa(
            modulus=public_key_params.modulus,
            public_exponent=public_key_params.public_exponent
        )
        public_key = PublicKey.from_params(params)
        self.assertEqual(params, public_key.params)
        self.assertEqual(public_key.key_size, 2048)

    def test_pem(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(public_key.pem, self._get_public_key_pem('snakeoil_cert_pubkey'))

    def test_der(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(public_key, PublicKey.from_der(public_key.der))

    def test_digest(self):
        public_key = self._get_public_key('snakeoil_cert_pubkey')
        self.assertEqual(
            public_key.get_digest(Hash.MD5),
            bytes_from_hex_string('5D:B2:D9:9F:97:5C:C6:19:B3:91:7E:F8:1A:37:2C:78', ':')
        )

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

    def test_asdict(self):
        public_key_x509 = self._get_public_key('gitlab.com_ssh_rsa_key')
        self.assertEqual(public_key_x509._asdict(), collections.OrderedDict([
            ('algorithm', Authentication.RSA),
            ('size', PublicKeySize(key_type=Authentication.RSA, value=2048)),
            ('fingerprints', collections.OrderedDict([
                (Hash.MD5, '94:33:7E:9C:56:1B:CE:19:FF:D3:50:DA:D4:AA:45:D7'),
                (Hash.SHA1, 'BC:14:22:BF:0B:65:89:FB:9E:1C:95:C3:B6:5C:2A:16:1D:82:DB:AE'),
                (
                    Hash.SHA2_256,
                    '34:8E:31:C3:D5:88:1E:09:A4:A9:30:8A:90:D9:46:5B:73:07:79:DE:DA:D2:D8:F2:C3:81:F2:54:24:6B:73:D7'
                )
            ]))
        ]))


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
            public_key_x509.get_digest(Hash.MD5),
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

    def test_asdict(self):
        public_key_x509 = self._get_public_key_x509('rsa2048.badssl.com')
        self.assertEqual(public_key_x509._asdict(), collections.OrderedDict([
            ('algorithm', Authentication.RSA),
            ('size', PublicKeySize(
                key_type=Authentication.RSA,
                value=2048,
            )),
            ('version', 'v3'),
            ('serial_number', '398674370847804942957222553262670217215220'),
            ('subject', collections.OrderedDict([('common_name', '*.badssl.com')])),
            ('subject_alternative_names', ['*.badssl.com', 'badssl.com']),
            ('issuer', collections.OrderedDict([
                ('country_name', 'US'),
                ('organization_name', "Let's Encrypt"),
                ('common_name', 'R3')
            ])),
            ('signature_hash_algorithm', Signature.RSA_WITH_SHA2_256),
            ('validity', collections.OrderedDict([
                ('not_before', '2023-04-23 23:00:10+00:00'),
                ('not_after', '2023-07-22 23:00:09+00:00'),
                ('period', '89 days, 23:59:59'),
                ('remaining', None)
            ])),
            ('revocation', collections.OrderedDict([
                ('crl_distribution_points', []),
                ('ocsp_responders', ['http://r3.o.lencr.org'])
            ])),
            ('fingerprints', collections.OrderedDict([
                (Hash.MD5, 'E5:CE:F4:ED:BB:42:C4:59:01:63:29:4B:DD:55:64:E2'),
                (Hash.SHA1, 'B8:68:EC:8E:5C:9F:C2:EC:B2:E5:A7:12:C5:B8:F2:34:B7:33:CD:44'),
                (
                    Hash.SHA2_256,
                    '17:7D:74:6A:01:B5:8C:CD:E4:5D:F9:09:48:E4:01:72:4D:83:6A:C6:E1:44:7F:11:2F:7E:20:C3:40:C0:2A:63'
                )
            ])),
            ('public_key_pin', '6Lkip0FxqykIPcMKjlwSSxNYRqG1EHcSNLMvN4uV1zc='),
            ('end_entity', collections.OrderedDict([
                ('extended_validation', False),
                ('tls_features', [])
            ]))
        ]))

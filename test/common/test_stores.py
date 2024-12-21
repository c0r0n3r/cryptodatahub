# -*- coding: utf-8 -*-

import collections
import unittest

from test.common.classes import TestClasses


from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.entity import Entity
from cryptodatahub.common.key import PublicKeyX509Base
from cryptodatahub.common.stores import (
    CertificateTransparencyLog,
    CertificateTransparencyLogParams,
    CertificateTransparencyLogUnknown,
    RootCertificate,
    RootCertificateParams,
    RootCertificateTrustStoreConstraint,
    convert_root_certificate_params,
)


class TestCertificateTransparencyLog(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return CertificateTransparencyLog

    def test_error_mmd_too_small(self):
        with self.assertRaises(ValueError) as context_manager:
            CertificateTransparencyLogParams(
                operator=Entity.GOOGLE,
                log_id='=',
                key=b'',
                url='',
                mmd=0
            )
        self.assertEqual(context_manager.exception.args, ('\'mmd\' must be >= 1: 0',))

    def test_from_log_id(self):
        self.assertEqual(
            CertificateTransparencyLog.from_log_id('lgbALGkAM6odFF9ZxuJkjQVJ8N+WqrjbkVpw2OzzkKU='),
            CertificateTransparencyLog.AKAMAI_CT_LOG.value
        )
        self.assertEqual(
            CertificateTransparencyLog.from_log_id(bytearray(b'unkown log')),
            CertificateTransparencyLogUnknown(bytearray(b'unkown log'))
        )

    def test_convert_description(self):
        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('CaMeL CaSe'),
            'CAMEL_CASE'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('S"p+e!c%i/a=l'),
            'S_P_E_C_I_A_L'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('S""p++e!!c%%i//a==l'),
            'S_P_E_C_I_A_L'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('  leading spaces'),
            'LEADING_SPACES'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('trailing spaces  '),
            'TRAILING_SPACES'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Log'),
            'ORGANIZATION_LOG'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Log 2'),
            'ORGANIZATION_LOG_2'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Log 2023'),
            'ORGANIZATION_LOG_2023'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Log 2023 2'),
            'ORGANIZATION_LOG_2023_2'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Log 2023H2'),
            'ORGANIZATION_LOG_2023H2'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Log v1 2023'),
            'ORGANIZATION_LOG_V1_2023'
        )

        self.assertEqual(
            CertificateTransparencyLogParams.description_to_enum_item_name('Organization Ct Log 2023'),
            'ORGANIZATION_CT_LOG_2023'
        )

    def test_str(self):
        self.assertEqual(
            str(CertificateTransparencyLog.from_log_id(bytearray(b'unknown log'))),
            'dW5rbm93biBsb2c='
        )
        self.assertEqual(
            str(CertificateTransparencyLog.AKAMAI_CT_LOG.value),
            'Akamai CT Log (lgbALGkAM6odFF9ZxuJkjQVJ8N+WqrjbkVpw2OzzkKU=)'
        )


class TestRootCertificateParams(TestClasses.TestKeyBase):
    def test_subject_to_enum_item_name(self):
        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'common_name': 'common name'},
                1
            ),
            'COMMON_NAME_1'
        )

        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'common_name': 'common name',
                 'organizational_unit_name': 'organizational unit'},
                1
            ),
            'COMMON_NAME_1'
        )

        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'common_name': 'common name',
                 'organization_name': 'organization'},
                1
            ),
            'COMMON_NAME_1'
        )

        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'organizational_unit_name': 'organizational unit'},
                1
            ),
            'ORGANIZATIONAL_UNIT_1'
        )

        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'organizational_unit_name': 'organizational unit',
                 'organization_name': 'organization'},
                1
            ),
            'ORGANIZATIONAL_UNIT_1'
        )

        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'organization_name': 'organization'},
                1
            ),
            'ORGANIZATION_1'
        )

        self.assertEqual(
            RootCertificateParams.subject_to_enum_item_name(
                {'common_name': ('common',
                                 'name')},
                1
            ),
            'COMMON_NAME_1'
        )

    def test_identifier(self):
        self.assertEqual(
            RootCertificateParams(self._get_public_key_x509('snakeoil_ca_cert')).identifier,
            'DEFAULT_COMPANY_CA_551843783816852671294343937890484223348994332352'
        )

    def test_asdict(self):
        self.assertEqual(
            RootCertificateParams(self._get_public_key_x509('snakeoil_ca_cert'))._asdict(),
            collections.OrderedDict([
                ('_meta', collections.OrderedDict([
                    ('_subject', collections.OrderedDict([
                        ('country_name', 'XX'),
                        ('locality_name', 'Default City'),
                        ('organization_name', 'Default Company Ltd'),
                        ('common_name', 'Default Company CA')
                    ])),
                    ('_fingerprints', collections.OrderedDict([
                        ('MD5',
                         'D5:34:BF:D6:13:2A:75:9C:A8:3D:AD:AC:CE:B3:9E:84'),
                        ('SHA1',
                         'F8:26:7B:11:7C:85:C7:EB:C6:0F:01:E2:66:2A:82:C9:42:12:4A:62'),
                        ('SHA2_256',
                         '8D:45:A1:27:4C:B4:51:AB:02:A6:37:C3:63:62:AF:65:'
                         '30:0F:A5:54:44:A6:E7:60:35:A7:45:79:E8:64:B9:D9')
                    ]))
                ])),
                ('certificate', [
                    '-----BEGIN CERTIFICATE-----',
                    'MIIDnzCCAoegAwIBAgIUYKmH9ghjSXftrJhqTq2zfLUJ1sAwDQYJKoZIhvcNAQEL',
                    'BQAwXzELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE',
                    'CgwTRGVmYXVsdCBDb21wYW55IEx0ZDEbMBkGA1UEAwwSRGVmYXVsdCBDb21wYW55',
                    'IENBMB4XDTIzMDUyOTE3Mjc0OVoXDTI4MDUyNzE3Mjc0OVowXzELMAkGA1UEBhMC',
                    'WFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UECgwTRGVmYXVsdCBDb21w',
                    'YW55IEx0ZDEbMBkGA1UEAwwSRGVmYXVsdCBDb21wYW55IENBMIIBIjANBgkqhkiG',
                    '9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueVK46q1gO6TRgDsSKJ1VHZO4GAMrholea/2',
                    'RR832DSRgI9wKC3KVrrc+RTev5l5JWlor8cctOLipxT8XsSeyH8S30pU38xkCyPL',
                    'zFVm7abJ1GXZcRQ/bJ241mgc8D4ugvsbsUPNX7ff1D/dGsSh4Rjpco2lEzw0kLFp',
                    'NmKkc2h1UUApSktWurewVFdcQ8I9u9OqD3tc0KeSMejzVBOkctcYChVAZRoTfXKV',
                    '9pvKIayFJN739zmJSWS2pxPNCgKp6sYMvMPpbU9AiTQYa1zenon/k6A94Gn3yWxG',
                    'tBpTN+vInTLZe1OmM9uXwOkFWjWbfaGYcOIrFGhhaMxSfOVeMwIDAQABo1MwUTAd',
                    'BgNVHQ4EFgQUx3cgEXkwESXclHhsdJWU63Vv8kUwHwYDVR0jBBgwFoAUx3cgEXkw',
                    'ESXclHhsdJWU63Vv8kUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC',
                    'AQEAibNgxyAIUurv1YCIsD9SmfeQTIQMT80d2K+Wc0u0tk5eVACV3HecmLz7JNU0',
                    'yPPkUVnG2/B93ZPpaYGuRFPC+r32ZZYZABRcgAJIVBqtCYxq8ZWY/vbY5F6SWdnJ',
                    'MsWhVgrjqmRNRQkhPNf/LJ8fvXk+BROODrtfYPDsHoVteaYQkdDrnahlbF5HhxeO',
                    'Iskcr9tFo4oUsZpUIOYiY3go14PfZuq1h11ULD1qf7e1H+Fk2knl820wFrgc6BTx',
                    'j/ftJD5c/0T7cnVov5veG0W6sU1MAYop8g/2Xc4eMtRfamiU5scLzpvl1OdxGExw',
                    'Ek966UKB55AyKxqVAQBRb3yeCw==',
                    '-----END CERTIFICATE-----'
                ]),
            ])
        )

    def test_get_constraints_by_owner(self):
        root_certificate_param = RootCertificateParams(RootCertificate.AAA_CERTIFICATE_SERVICES_1.value.certificate)
        with self.assertRaises(KeyError) as context_manager:
            root_certificate_param.get_constraints_by_owner(Entity.APPLE)
        self.assertEqual(context_manager.exception.args, (Entity.APPLE, ))

        root_certificate_param = RootCertificateParams(
            RootCertificate.AAA_CERTIFICATE_SERVICES_1.value.certificate,
            [RootCertificateTrustStoreConstraint(Entity.GOOGLE)]
        )
        with self.assertRaises(KeyError) as context_manager:
            root_certificate_param.get_constraints_by_owner(Entity.APPLE)
        self.assertEqual(context_manager.exception.args, (Entity.APPLE, ))

        root_certificate_param = RootCertificateParams(
            RootCertificate.AAA_CERTIFICATE_SERVICES_1.value.certificate,
            [RootCertificateTrustStoreConstraint(Entity.APPLE)]
        )
        self.assertEqual(root_certificate_param.get_constraints_by_owner(Entity.APPLE), ())


class TestRootCertificateParamCertificateConverter(unittest.TestCase):
    def test_error_invalid_type(self):
        original_value = 1234
        converted_value = convert_root_certificate_params()(original_value)
        self.assertEqual(id(original_value), id(convert_root_certificate_params()(converted_value)))

    def test_error_invalid_value(self):
        original_value = ()
        converted_value = convert_root_certificate_params()(original_value)
        self.assertEqual(id(converted_value), id(convert_root_certificate_params()(converted_value)))

    def test_none(self):
        converted_value = convert_root_certificate_params()(None)
        self.assertEqual(converted_value, None)

    def test_convert(self):
        original_value = [
            '-----BEGIN CERTIFICATE-----',
            'MIIDnzCCAoegAwIBAgIUYKmH9ghjSXftrJhqTq2zfLUJ1sAwDQYJKoZIhvcNAQEL',
            'BQAwXzELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE',
            'CgwTRGVmYXVsdCBDb21wYW55IEx0ZDEbMBkGA1UEAwwSRGVmYXVsdCBDb21wYW55',
            'IENBMB4XDTIzMDUyOTE3Mjc0OVoXDTI4MDUyNzE3Mjc0OVowXzELMAkGA1UEBhMC',
            'WFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UECgwTRGVmYXVsdCBDb21w',
            'YW55IEx0ZDEbMBkGA1UEAwwSRGVmYXVsdCBDb21wYW55IENBMIIBIjANBgkqhkiG',
            '9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueVK46q1gO6TRgDsSKJ1VHZO4GAMrholea/2',
            'RR832DSRgI9wKC3KVrrc+RTev5l5JWlor8cctOLipxT8XsSeyH8S30pU38xkCyPL',
            'zFVm7abJ1GXZcRQ/bJ241mgc8D4ugvsbsUPNX7ff1D/dGsSh4Rjpco2lEzw0kLFp',
            'NmKkc2h1UUApSktWurewVFdcQ8I9u9OqD3tc0KeSMejzVBOkctcYChVAZRoTfXKV',
            '9pvKIayFJN739zmJSWS2pxPNCgKp6sYMvMPpbU9AiTQYa1zenon/k6A94Gn3yWxG',
            'tBpTN+vInTLZe1OmM9uXwOkFWjWbfaGYcOIrFGhhaMxSfOVeMwIDAQABo1MwUTAd',
            'BgNVHQ4EFgQUx3cgEXkwESXclHhsdJWU63Vv8kUwHwYDVR0jBBgwFoAUx3cgEXkw',
            'ESXclHhsdJWU63Vv8kUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC',
            'AQEAibNgxyAIUurv1YCIsD9SmfeQTIQMT80d2K+Wc0u0tk5eVACV3HecmLz7JNU0',
            'yPPkUVnG2/B93ZPpaYGuRFPC+r32ZZYZABRcgAJIVBqtCYxq8ZWY/vbY5F6SWdnJ',
            'MsWhVgrjqmRNRQkhPNf/LJ8fvXk+BROODrtfYPDsHoVteaYQkdDrnahlbF5HhxeO',
            'Iskcr9tFo4oUsZpUIOYiY3go14PfZuq1h11ULD1qf7e1H+Fk2knl820wFrgc6BTx',
            'j/ftJD5c/0T7cnVov5veG0W6sU1MAYop8g/2Xc4eMtRfamiU5scLzpvl1OdxGExw',
            'Ek966UKB55AyKxqVAQBRb3yeCw==',
            '-----END CERTIFICATE-----',
        ]
        converted_value = convert_root_certificate_params()(original_value)
        self.assertTrue(isinstance(converted_value, PublicKeyX509Base))
        self.assertEqual(id(converted_value), id(convert_root_certificate_params()(converted_value)))

    def test_repr(self):
        self.assertEqual(repr(convert_root_certificate_params()), '<root certificate parameter converter>')


class TestRootCertificate(unittest.TestCase):
    def test_get_items_by_trust_owner(self):
        root_certificate_count_by_owner = collections.OrderedDict([
            (Entity.MOZILLA, 141),
            (Entity.MICROSOFT, 299),
            (Entity.APPLE, 172),
            (Entity.GOOGLE, 134),
        ])

        for owner, certificate_count in root_certificate_count_by_owner.items():
            with self.subTest(owner=owner):
                root_certificates = RootCertificate.get_items_by_trust_owner(owner)
                self.assertEqual(len(root_certificates), certificate_count)
                self.assertEqual(id(root_certificates), id(RootCertificate.get_items_by_trust_owner(owner)))

    def test_get_item_by_fingerprint(self):
        root_certificate = RootCertificate.AAA_CERTIFICATE_SERVICES_1.value.certificate
        sha2_256_fingerprint = root_certificate.fingerprints[Hash.SHA2_256]
        self.assertEqual(
            RootCertificate.get_item_by_sha2_256_fingerprint(sha2_256_fingerprint),
            RootCertificate.AAA_CERTIFICATE_SERVICES_1
        )
        self.assertEqual(
            RootCertificate.get_item_by_sha2_256_fingerprint(sha2_256_fingerprint.replace(':',
                                                                                          '')),
            RootCertificate.AAA_CERTIFICATE_SERVICES_1
        )

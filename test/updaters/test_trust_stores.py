# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

from unittest import mock

import argparse
import base64
import collections
import csv
import datetime
import io
import json
import os
import tarfile

from test.common.classes import TestClasses
from test.updaters.classes import MockSelectedStoreFetcher

import asn1crypto.cms
import asn1crypto.core
import asn1crypto.pkcs12
import asn1crypto.x509

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.entity import Entity
from cryptodatahub.common.fetcher import (
    CertificatePemFetcher,
    FetcherRootCertificateStore,
    FetcherRootCertificateStoreApple,
    FetcherRootCertificateStoreAndroid,
    FetcherRootCertificateStoreChrome,
    FetcherRootCertificateStoreMicrosoft,
    FetcherRootCertificateStoreMozilla,
    FetcherRootCertificateStoreOracleJDK,
)
from cryptodatahub.common.stores import (
    CertificateTrustConstraint,
    RootCertificateBase,
    RootCertificateParams,
    RootCertificateTrustConstraintAction,
    RootCertificateTrustStoreConstraint,
    RootCertificate,
)
from cryptodatahub.common.types import Base64Data
from cryptodatahub.common.utils import HttpFetcher

from updaters.common import UpdaterBase
from updaters.trust_stores import (
    RootCertificateStore,
    UpdaterRootCertificateTrustStore,
    _parse_trust_store_owner,
    main,
)
import updaters.trust_stores as trust_stores_module


class TestRootCertificateBase(TestClasses.TestKeyBase):
    def setUp(self):
        super().setUp()

        # Mock CertificatePemFetcher to prevent external HTTP calls
        self.mock_certificate_pem_fetcher = mock.Mock(spec=CertificatePemFetcher)
        self.mock_certificate_pem_fetcher.return_value = ''  # Return empty string for certificate PEMs
        self.certificate_pem_fetcher_patcher = mock.patch(
            'cryptodatahub.common.fetcher.CertificatePemFetcher',
            return_value=self.mock_certificate_pem_fetcher
        )
        self.certificate_pem_fetcher_patcher.start()
        self.addCleanup(self.certificate_pem_fetcher_patcher.stop)

        self.public_key_x509_lets_encrypt = self._get_public_key_x509('letsencrypt_isrg_root_x1')
        self.public_key_x509_snakeoil_ca = self._get_public_key_x509('snakeoil_ca_cert')

    @staticmethod
    def _get_mock_data_mozilla(public_keys=(), options=None):
        mock_data = io.StringIO()
        dict_writer = csv.DictWriter(
            mock_data, FetcherRootCertificateStoreMozilla.CSV_FIELDS,
            quotechar='"', quoting=csv.QUOTE_ALL
        )
        dict_writer.writeheader()

        if options is None:
            options = len(public_keys) * [{}]

        for i, public_key in enumerate(public_keys):
            dict_writer.writerow(dict(options[i], **{'PEM': public_key.pem}))

        return mock_data.getvalue().encode('ascii')

    @staticmethod
    def _get_mock_data_microsoft(public_keys=(), options=None):
        mock_data = io.StringIO()
        dict_writer = csv.DictWriter(
            mock_data, FetcherRootCertificateStoreMicrosoft.CSV_FIELDS,
            quotechar='"', quoting=csv.QUOTE_ALL
        )
        dict_writer.writeheader()

        if options is None:
            options = len(public_keys) * [{}]

        for i, public_key in enumerate(public_keys):
            dict_writer.writerow(dict(options[i], **{'PEM': public_key.pem}))

        return mock_data.getvalue().encode('ascii')

    @staticmethod
    def _get_mock_data_apple(public_keys=()):
        mock_data = os.linesep.join([
            '<h2 id="trusted">Trusted Certificates</h2>',
            '<tbody>',
            '<tr>',
        ] + [
            f'<th>{field_name}</th>'
            for field_name in FetcherRootCertificateStoreApple.FIELDS
        ] + [
            '</tr>',
        ])

        for public_key in public_keys:
            mock_data += '<tr>' + os.linesep
            for field_name in FetcherRootCertificateStoreApple.FIELDS:
                if field_name == 'Fingerprint (SHA-256)':
                    data = public_key.fingerprints[Hash.SHA2_256].replace(':', ' ')
                else:
                    data = field_name

                mock_data += f'<td>{data}</td>{os.linesep}'
            mock_data += '</tr>' + os.linesep

        return mock_data.encode('ascii')

    @staticmethod
    def _get_mock_data_android(public_keys=()):
        commit_log = b")]}\'\n" + json.dumps({'log': [{'commit': 'deadbeef'}]}).encode('ascii')
        entries = [
            {'name': public_key.fingerprints[Hash.SHA2_256], 'type': 'blob'}
            for public_key in public_keys
        ]
        listing = b")]}'\n" + json.dumps({'entries': entries}).encode('ascii')

        file_contents = [
            base64.b64encode(public_key.pem.encode('ascii'))
            for public_key in public_keys
        ]

        return [commit_log, listing] + file_contents

    @staticmethod
    def _get_mock_data_chrome(public_keys=()):
        commit_log = b")]}\'\n" + json.dumps({'log': [{'commit': 'deadbeef'}]}).encode('ascii')
        certs_blob = base64.b64encode(
            ''.join(public_key.pem for public_key in public_keys).encode('ascii')
        )
        return [commit_log, certs_blob]

    @staticmethod
    def _build_jdk_pfx(public_keys, extra_content_infos, extra_safe_bags):
        """Build a PKCS#12 Pfx structure with certificates."""
        safe_bags = list(extra_safe_bags)
        for pk in public_keys:
            cert_bag = asn1crypto.pkcs12.CertBag({
                'cert_id': '1.2.840.113549.1.9.22.1',  # x509
                'cert_value': asn1crypto.core.ParsableOctetString(pk.der),
            })
            safe_bag = asn1crypto.pkcs12.SafeBag({
                'bag_id': '1.2.840.113549.1.12.10.1.3',  # cert_bag
                'bag_value': cert_bag,
            })
            safe_bags.append(safe_bag)

        safe_contents = asn1crypto.pkcs12.SafeContents(safe_bags)
        inner_content_info = asn1crypto.cms.ContentInfo({
            'content_type': '1.2.840.113549.1.7.1',  # data
            'content': asn1crypto.core.OctetString(safe_contents.dump()),
        })
        auth_safe = asn1crypto.pkcs12.AuthenticatedSafe(
            list(extra_content_infos) + [inner_content_info]
        )

        return asn1crypto.pkcs12.Pfx({
            'version': 3,
            'auth_safe': asn1crypto.cms.ContentInfo({
                'content_type': '1.2.840.113549.1.7.1',  # data
                'content': asn1crypto.core.OctetString(auth_safe.dump()),
            }),
        })

    @staticmethod
    def _get_mock_data_jdk_cacerts(public_keys=(), extra_content_infos=(), extra_safe_bags=()):
        """Build a minimal JDK-like tar.gz archive containing a PKCS#12 cacerts keystore.

        The archive has a single member at 'jdk-21/lib/security/cacerts' which holds
        a minimal PKCS#12 structure with unencrypted certBag entries — matching the
        format that Oracle JDK 21 uses for its root CA store.
        """
        pfx = TestRootCertificateBase._build_jdk_pfx(public_keys, extra_content_infos, extra_safe_bags)
        p12_bytes = pfx.dump()

        mock_tar = io.BytesIO()
        with tarfile.open(fileobj=mock_tar, mode='w:gz') as tar:
            tarinfo = tarfile.TarInfo('jdk-21/lib/security/cacerts')
            tarinfo.size = len(p12_bytes)
            tar.addfile(tarinfo, io.BytesIO(p12_bytes))
        return mock_tar.getvalue()

    @staticmethod
    def _get_mock_data_jdk_no_cacerts():
        """Build a tar.gz archive that contains no cacerts keystore entry."""
        mock_tar = io.BytesIO()
        with tarfile.open(fileobj=mock_tar, mode='w:gz') as tar:
            dummy = b'not-a-keystore'
            tarinfo = tarfile.TarInfo('jdk-21/lib/security/other')
            tarinfo.size = len(dummy)
            tar.addfile(tarinfo, io.BytesIO(dummy))
        return mock_tar.getvalue()


class TestCertificatePemFetcher(TestClasses.TestKeyBase):
    def test_returns_pem_from_root_certificate_store(self):
        certificate_pem_fetcher = CertificatePemFetcher()
        expected_pem = self._get_public_key_x509('snakeoil_ca_cert').pem

        with mock.patch.object(
            RootCertificate,
            'get_item_by_sha2_256_fingerprint',
            return_value=mock.Mock(value=mock.Mock(certificate=mock.Mock(pem=expected_pem))),
        ):
            actual_pem = certificate_pem_fetcher('dummy-fingerprint')

        self.assertEqual(actual_pem, expected_pem)

    def test_fetches_pem_from_crt_sh_when_missing_in_store(self):
        certificate_pem_fetcher = CertificatePemFetcher()
        expected_pem = '-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----'

        with mock.patch.object(
            RootCertificate,
            'get_item_by_sha2_256_fingerprint',
            side_effect=KeyError,
        ), mock.patch.object(
            type(certificate_pem_fetcher.http_fetcher),
            '__call__',
            return_value=(expected_pem + '\n').encode('utf-8'),
        ) as mocked_http_fetch:
            actual_pem = certificate_pem_fetcher('abc123')

        self.assertEqual(actual_pem, expected_pem)
        mocked_http_fetch.assert_called_once_with('https://crt.sh/?d=abc123')


class TestUpdaterRootCertificateStoreAndroid(TestRootCertificateBase):
    def test_parse_empty(self):
        with mock.patch.object(HttpFetcher, '__call__', side_effect=self._get_mock_data_android()):
            root_certificate_store = FetcherRootCertificateStoreAndroid.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')
        mock_data = self._get_mock_data_android([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data):
            root_certificate_store = FetcherRootCertificateStoreAndroid.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })


class TestUpdaterRootCertificateStoreChrome(TestRootCertificateBase):
    def test_parse_empty(self):
        with mock.patch.object(HttpFetcher, '__call__', side_effect=self._get_mock_data_chrome()):
            root_certificate_store = FetcherRootCertificateStoreChrome.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')
        mock_data = self._get_mock_data_chrome([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data):
            root_certificate_store = FetcherRootCertificateStoreChrome.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })


class TestUpdaterRootCertificateStoreApple(TestRootCertificateBase):
    def test_parse_empty(self):
        with mock.patch.object(HttpFetcher, '__call__', return_value=self._get_mock_data_apple()):
            root_certificate_store = FetcherRootCertificateStoreApple.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')
        mock_data_apple = self._get_mock_data_apple([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data_apple), mock.patch(
            'cryptodatahub.common.fetcher.CertificatePemFetcher'
        ) as mock_certificate_pem_fetcher:
            mock_certificate_pem_fetcher.return_value.return_value = public_key_x509.pem
            root_certificate_store = FetcherRootCertificateStoreApple.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })


class TestUpdaterRootCertificateStoreMicrosoft(TestRootCertificateBase):
    def test_parse_empty(self):
        mock_data = self._get_mock_data_microsoft()
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')

        mock_data_microsoft = self._get_mock_data_microsoft([public_key_x509])

        with mock.patch.object(HttpFetcher, '__call__', side_effect=[
            mock_data_microsoft,
            mock_data_microsoft,
            mock_data_microsoft,
            mock_data_microsoft,
        ]), mock.patch.object(CertificatePemFetcher, '__call__', return_value=public_key_x509.pem):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })

    def test_parse_status_disabled(self):
        mock_data = self._get_mock_data_microsoft(
            [self.public_key_x509_snakeoil_ca, self.public_key_x509_lets_encrypt],
        )
        mock_data = [
            mock_data,
            mock_data,
            mock_data,
            mock_data,
        ]

        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data), mock.patch.object(
            CertificatePemFetcher,
            '__call__',
            return_value=self.public_key_x509_snakeoil_ca.pem,
        ):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 2)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(self.public_key_x509_snakeoil_ca.pem.splitlines()): (),
            tuple(self.public_key_x509_lets_encrypt.pem.splitlines()): (),
        })

    def test_parse_status_not_before(self):
        mock_data = self._get_mock_data_microsoft(
            [self.public_key_x509_snakeoil_ca, self.public_key_x509_lets_encrypt],
        )
        mock_data = [mock_data, mock_data, mock_data, mock_data]

        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data), mock.patch.object(
            CertificatePemFetcher,
            '__call__',
            return_value=self.public_key_x509_snakeoil_ca.pem,
        ):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 2)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(self.public_key_x509_snakeoil_ca.pem.splitlines()): (),
            tuple(self.public_key_x509_lets_encrypt.pem.splitlines()): (),
        })

    def test_parse_pem_only_row(self):
        current_data = [
            {'PEM': self.public_key_x509_snakeoil_ca.pem},
        ]

        parsed_data = FetcherRootCertificateStoreMicrosoft._transform_data(  # pylint: disable=protected-access
            current_data
        )

        self.assertEqual(parsed_data, {
            tuple(self.public_key_x509_snakeoil_ca.pem.splitlines()): (),
        })


class TestUpdaterRootCertificateStoreMozilla(TestRootCertificateBase):
    def test_parse_empty(self):
        mock_data = self._get_mock_data_mozilla()
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('letsencrypt_isrg_root_x1')

        mock_data = self._get_mock_data_mozilla([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', side_effect=[mock_data]):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })

    def test_parse_constraint_date(self):
        public_key_x509 = self._get_public_key_x509('letsencrypt_isrg_root_x1')

        mock_data = self._get_mock_data_mozilla(
            [public_key_x509],
            [{'Distrust for TLS After Date': '1970.01.01'}]
        )
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (
                CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    date=datetime.datetime(1970, 1, 1),
                ),
            )
        })

    def test_parse_constraint_domains(self):
        public_key_x509 = self._get_public_key_x509('letsencrypt_isrg_root_x1')

        mock_data = self._get_mock_data_mozilla(
            [public_key_x509],
            [{'Mozilla Applied Constraints': 'domain'}]
        )
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (
                CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    domains=["domain"],
                ),
            )
        })


class TestUpdaterRootCertificateStoreOracleJDK(TestRootCertificateBase):
    def test_parse_empty(self):
        mock_data = self._get_mock_data_jdk_cacerts()
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreOracleJDK.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')
        mock_data = self._get_mock_data_jdk_cacerts([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreOracleJDK.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })

    def test_download_url(self):
        expected_url = (
            f'https://download.oracle.com/java/{FetcherRootCertificateStoreOracleJDK.ORACLE_JDK_VERSION}/latest/'
            f'jdk-{FetcherRootCertificateStoreOracleJDK.ORACLE_JDK_VERSION}_linux-x64_bin.tar.gz'
        )
        self.assertEqual(FetcherRootCertificateStoreOracleJDK.get_tarball_url(), expected_url)

    def test_transform_data_accepts_octet_string(self):
        octet_string_certificate = asn1crypto.core.OctetString(self.public_key_x509_snakeoil_ca.der)
        fake_bag = {
            'bag_id': mock.Mock(native='cert_bag'),
            'bag_value': {
                'cert_value': octet_string_certificate,
            },
        }
        fake_content_info = {
            'content_type': mock.Mock(native='data'),
            'content': mock.Mock(native=b'ignored'),
        }
        fake_pfx = mock.Mock(authenticated_safe=[fake_content_info])

        with mock.patch.object(asn1crypto.pkcs12.Pfx, 'load', return_value=fake_pfx), mock.patch.object(
            asn1crypto.pkcs12.SafeContents, 'load', return_value=[fake_bag]
        ):
            parsed_data = FetcherRootCertificateStoreOracleJDK._transform_data(  # pylint: disable=protected-access
                b'ignored'
            )

        self.assertEqual(len(parsed_data), 1)

    def test_transform_data_accepts_certificate_sequence(self):
        certificate = asn1crypto.x509.Certificate.load(self.public_key_x509_snakeoil_ca.der)
        fake_bag = {
            'bag_id': mock.Mock(native='cert_bag'),
            'bag_value': {
                'cert_value': certificate,
            },
        }
        fake_content_info = {
            'content_type': mock.Mock(native='data'),
            'content': mock.Mock(native=b'ignored'),
        }
        fake_pfx = mock.Mock(authenticated_safe=[fake_content_info])

        with mock.patch.object(asn1crypto.pkcs12.Pfx, 'load', return_value=fake_pfx), mock.patch.object(
            asn1crypto.pkcs12.SafeContents, 'load', return_value=[fake_bag]
        ):
            parsed_data = FetcherRootCertificateStoreOracleJDK._transform_data(  # pylint: disable=protected-access
                b'ignored'
            )

        self.assertEqual(len(parsed_data), 1)

    def test_transform_data_uses_fallback_contents(self):
        class FallbackCertificate:
            def __init__(self, contents):
                self.contents = contents

        fallback_certificate = FallbackCertificate(self.public_key_x509_snakeoil_ca.der)
        fake_bag = {
            'bag_id': mock.Mock(native='cert_bag'),
            'bag_value': {
                'cert_value': fallback_certificate,
            },
        }
        fake_content_info = {
            'content_type': mock.Mock(native='data'),
            'content': mock.Mock(native=b'ignored'),
        }
        fake_pfx = mock.Mock(authenticated_safe=[fake_content_info])

        with mock.patch.object(asn1crypto.pkcs12.Pfx, 'load', return_value=fake_pfx), mock.patch.object(
            asn1crypto.pkcs12.SafeContents, 'load', return_value=[fake_bag]
        ):
            parsed_data = FetcherRootCertificateStoreOracleJDK._transform_data(  # pylint: disable=protected-access
                b'ignored'
            )

        self.assertEqual(len(parsed_data), 1)


class UpdaterRootCertificateTrustStoreTest(UpdaterBase):
    def __init__(self):
        root_certificate_test_class = RootCertificateBase(
            'RootCertificate', RootCertificateBase.get_json_records(RootCertificateParams)
        )

        super().__init__(
            fetcher_class=FetcherRootCertificateStore,
            enum_class=root_certificate_test_class,
            enum_param_class=RootCertificateParams,
        )


class TestFetcherRootCertificateStore(TestRootCertificateBase):
    def test_parse_empty(self):
        mock_data_chrome = self._get_mock_data_chrome()
        mock_data_android = self._get_mock_data_android()
        http_fetcher_results = [
            self._get_mock_data_mozilla(),
            mock_data_chrome[0],
            mock_data_chrome[1],
            mock_data_android[0],
            mock_data_android[1],
            self._get_mock_data_microsoft(),
            self._get_mock_data_apple(),
            self._get_mock_data_jdk_cacerts(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 0)

    def test_parse_single_item_in_store(self):
        mock_data_mozilla = self._get_mock_data_mozilla([self.public_key_x509_lets_encrypt])
        mock_data_chrome = self._get_mock_data_chrome()
        mock_data_android = self._get_mock_data_android()
        mock_data_microsoft = self._get_mock_data_microsoft([self.public_key_x509_snakeoil_ca])
        http_fetcher_results = [
            mock_data_mozilla,
            mock_data_chrome[0],
            mock_data_chrome[1],
            mock_data_android[0],
            mock_data_android[1],
            mock_data_microsoft,
            self._get_mock_data_apple(),
            self._get_mock_data_jdk_cacerts(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results), \
             mock.patch.object(CertificatePemFetcher, '__call__', return_value=self.public_key_x509_snakeoil_ca.pem):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 2)
        fetched_by_identifier = {
            root_certificate_param.identifier: root_certificate_param
            for root_certificate_param in fetched_data.parsed_data
        }

        lets_encrypt_identifier = RootCertificateParams(certificate=tuple(
            self.public_key_x509_lets_encrypt.pem.splitlines())
        ).identifier
        snakeoil_identifier = RootCertificateParams(certificate=tuple(
            self.public_key_x509_snakeoil_ca.pem.splitlines())
        ).identifier

        self.assertEqual(
            tuple(
                trust_store.owner
                for trust_store in fetched_by_identifier[lets_encrypt_identifier].trust_stores
            ),
            (Entity.MOZILLA,),
        )
        self.assertEqual(
            tuple(
                trust_store.owner
                for trust_store in fetched_by_identifier[snakeoil_identifier].trust_stores
            ),
            (Entity.MICROSOFT,),
        )

    def test_parse_multiple_item_in_store(self):
        mock_data_mozilla = self._get_mock_data_mozilla([
            self.public_key_x509_lets_encrypt,
            self.public_key_x509_snakeoil_ca,
        ])
        mock_data_chrome = self._get_mock_data_chrome()
        mock_data_android = self._get_mock_data_android()
        mock_data_microsoft = self._get_mock_data_microsoft([
            self.public_key_x509_lets_encrypt,
            self.public_key_x509_snakeoil_ca
        ])
        http_fetcher_results = [
            mock_data_mozilla,
            mock_data_chrome[0],
            mock_data_chrome[1],
            mock_data_android[0],
            mock_data_android[1],
            mock_data_microsoft,
            self._get_mock_data_apple(),
            self._get_mock_data_jdk_cacerts(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results), \
             mock.patch.object(CertificatePemFetcher, '__call__', return_value=self.public_key_x509_snakeoil_ca.pem):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 2)
        self.assertEqual(
            [root_certificate.identifier for root_certificate in fetched_data.parsed_data],
            sorted([root_certificate.identifier for root_certificate in fetched_data.parsed_data]),
        )

        for root_certificate_param in fetched_data.parsed_data:
            trust_stores = root_certificate_param.trust_stores
            self.assertEqual(
                tuple(trust_store.owner for trust_store in trust_stores),
                (Entity.MICROSOFT, Entity.MOZILLA),
            )
        for root_certificate_param in fetched_data.parsed_data:
            trust_stores = root_certificate_param.trust_stores
            for trust_store in trust_stores:
                constraints = trust_store.constraints
                self.assertEqual(len(constraints), 0)


class TestRootCertificateStore(TestRootCertificateBase):
    def test_default(self):
        root_certificate_store = RootCertificateStore()
        self.assertEqual(root_certificate_store.certificates, {})

    def test_with_certificates(self):
        base64_data = Base64Data(b'test data')
        constraint_action = RootCertificateTrustConstraintAction.DISTRUST
        root_certificate_store = RootCertificateStore(
            certificates={base64_data: constraint_action}
        )
        self.assertEqual(root_certificate_store.certificates, {base64_data: constraint_action})

    def test_error_invalid_key_type(self):
        with self.assertRaises(TypeError):
            RootCertificateStore(certificates={'invalid': RootCertificateTrustConstraintAction.DISTRUST})

    def test_error_invalid_value_type(self):
        with self.assertRaises(TypeError):
            RootCertificateStore(certificates={Base64Data(b'test'): 'invalid'})


class TestUpdaterRootCertificateTrustStoreSelection(TestRootCertificateBase):
    def test_parse_trust_store_owner_all(self):
        self.assertIsNone(_parse_trust_store_owner('all'))

    def test_parse_trust_store_owner_google(self):
        self.assertEqual(_parse_trust_store_owner('google'), Entity.GOOGLE)

    def test_parse_trust_store_owner_invalid(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            _parse_trust_store_owner('not-a-store')

    def test_updater_uses_default_fetcher_when_all_selected(self):
        updater = UpdaterRootCertificateTrustStore()
        self.assertEqual(updater.fetcher_class, FetcherRootCertificateStore)

    def test_selected_store_merges_existing_data(self):
        root_certificate_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())
        root_certificate_identifier = RootCertificateParams(
            certificate=root_certificate_pem_lines,
        ).identifier
        existing_root_certificates = collections.OrderedDict([
            (
                root_certificate_identifier,
                RootCertificateParams(
                    certificate=root_certificate_pem_lines,
                    trust_stores=(
                        RootCertificateTrustStoreConstraint(Entity.MOZILLA, ()),
                        RootCertificateTrustStoreConstraint(Entity.ANDROID, ()),
                    ),
                ),
            ),
        ])

        current_android_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['example.com'],
            ),
        )

        class CurrentAndroidStore:
            parsed_data = {
                root_certificate_pem_lines: current_android_constraints,
            }

        with mock.patch.object(
            FetcherRootCertificateStoreAndroid,
            'from_current_data',
            return_value=CurrentAndroidStore(),
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            updater = UpdaterRootCertificateTrustStore(Entity.ANDROID)
            merged_data = updater.fetcher_class.from_current_data()

        self.assertEqual(len(merged_data.parsed_data), 1)
        merged_root_certificate = merged_data.parsed_data[0]
        self.assertEqual(tuple(merged_root_certificate.certificate.pem.splitlines()), root_certificate_pem_lines)
        self.assertEqual(len(merged_root_certificate.trust_stores), 2)
        self.assertEqual(
            tuple(trust_store.owner for trust_store in merged_root_certificate.trust_stores),
            (Entity.ANDROID, Entity.MOZILLA),
        )
        self.assertEqual(merged_root_certificate.get_constraints_by_owner(Entity.ANDROID), current_android_constraints)

    def test_selected_store_adds_missing_owner_and_new_certificate(self):
        existing_root_certificate_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())
        existing_root_certificate_identifier = RootCertificateParams(
            certificate=existing_root_certificate_pem_lines,
        ).identifier
        existing_root_certificates = collections.OrderedDict([
            (
                existing_root_certificate_identifier,
                RootCertificateParams(
                    certificate=existing_root_certificate_pem_lines,
                    trust_stores=(
                        RootCertificateTrustStoreConstraint(Entity.MOZILLA, ()),
                    ),
                ),
            ),
        ])

        new_root_certificate_pem_lines = tuple(self.public_key_x509_lets_encrypt.pem.splitlines())
        current_android_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['example.com'],
            ),
        )

        class CurrentAndroidStore:
            parsed_data = {
                existing_root_certificate_pem_lines: current_android_constraints,
                new_root_certificate_pem_lines: (),
            }

        with mock.patch.object(
            FetcherRootCertificateStoreAndroid,
            'from_current_data',
            return_value=CurrentAndroidStore(),
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            updater = UpdaterRootCertificateTrustStore(Entity.ANDROID)
            merged_data = updater.fetcher_class.from_current_data()

        self.assertEqual(len(merged_data.parsed_data), 2)

        merged_by_certificate = {
            tuple(root_certificate.certificate.pem.splitlines()): root_certificate
            for root_certificate in merged_data.parsed_data
        }

        existing_root_certificate = merged_by_certificate[existing_root_certificate_pem_lines]
        self.assertEqual(
            tuple(trust_store.owner for trust_store in existing_root_certificate.trust_stores),
            (Entity.ANDROID, Entity.MOZILLA),
        )
        self.assertEqual(
            existing_root_certificate.get_constraints_by_owner(Entity.ANDROID),
            current_android_constraints,
        )
        self.assertEqual(
            existing_root_certificate.get_constraints_by_owner(Entity.MOZILLA),
            (),
        )

        new_root_certificate = merged_by_certificate[new_root_certificate_pem_lines]
        self.assertEqual(
            tuple(trust_store.owner for trust_store in new_root_certificate.trust_stores),
            (Entity.ANDROID,),
        )
        self.assertEqual(new_root_certificate.get_constraints_by_owner(Entity.ANDROID), ())

    def test_selected_store_preserves_existing_owners(self):
        root_certificate_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())
        existing_root_certificate = RootCertificateParams(
            certificate=root_certificate_pem_lines,
            trust_stores=(
                RootCertificateTrustStoreConstraint(Entity.MOZILLA, ()),
                RootCertificateTrustStoreConstraint(Entity.MICROSOFT, ()),
            ),
        )
        existing_root_certificates = collections.OrderedDict([
            (
                'JSON_RECORD_KEY_DOES_NOT_MATCH_IDENTIFIER',
                existing_root_certificate,
            ),
        ])

        current_google_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['example.com'],
            ),
        )

        MockSelectedStoreFetcher.parsed_data = {
            root_certificate_pem_lines: current_google_constraints,
        }

        with mock.patch.object(
            FetcherRootCertificateStore,
            'get_root_certificate_store_updaters',
            return_value={Entity.GOOGLE: MockSelectedStoreFetcher},
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            selected_fetcher = (
                trust_stores_module._get_selected_trust_store_fetcher_class(  # pylint: disable=protected-access
                    Entity.GOOGLE
                )
            )
            merged_data = selected_fetcher.from_current_data()

        self.assertEqual(len(merged_data.parsed_data), 1)
        merged_root_certificate = merged_data.parsed_data[0]
        self.assertEqual(
            merged_root_certificate.trust_stores,
            (
                RootCertificateTrustStoreConstraint(Entity.GOOGLE, current_google_constraints),
                RootCertificateTrustStoreConstraint(Entity.MICROSOFT, ()),
                RootCertificateTrustStoreConstraint(Entity.MOZILLA, ()),
            ),
        )
        self.assertEqual(
            merged_root_certificate.get_constraints_by_owner(Entity.MOZILLA),
            (),
        )
        self.assertEqual(
            merged_root_certificate.get_constraints_by_owner(Entity.MICROSOFT),
            (),
        )
        self.assertEqual(
            merged_root_certificate.get_constraints_by_owner(Entity.GOOGLE),
            current_google_constraints,
        )

    def test_selected_store_removes_selected_owner_when_missing_from_current_data(self):
        root_certificate_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())
        existing_root_certificate = RootCertificateParams(
            certificate=root_certificate_pem_lines,
            trust_stores=(
                RootCertificateTrustStoreConstraint(Entity.MOZILLA, ()),
                RootCertificateTrustStoreConstraint(Entity.GOOGLE, ()),
                RootCertificateTrustStoreConstraint(Entity.MICROSOFT, ()),
            ),
        )
        existing_root_certificates = collections.OrderedDict([
            ('ANY_KEY', existing_root_certificate),
        ])

        MockSelectedStoreFetcher.parsed_data = {}

        with mock.patch.object(
            FetcherRootCertificateStore,
            'get_root_certificate_store_updaters',
            return_value={Entity.GOOGLE: MockSelectedStoreFetcher},
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            selected_fetcher = (
                trust_stores_module._get_selected_trust_store_fetcher_class(  # pylint: disable=protected-access
                    Entity.GOOGLE
                )
            )
            merged_data = selected_fetcher.from_current_data()

        self.assertEqual(len(merged_data.parsed_data), 1)
        merged_root_certificate = merged_data.parsed_data[0]
        self.assertEqual(
            merged_root_certificate.trust_stores,
            (
                RootCertificateTrustStoreConstraint(Entity.MICROSOFT, ()),
                RootCertificateTrustStoreConstraint(Entity.MOZILLA, ()),
            ),
        )

    def test_selected_store_drops_certificate_when_selected_owner_was_last_owner(self):
        root_certificate_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())
        existing_root_certificate = RootCertificateParams(
            certificate=root_certificate_pem_lines,
            trust_stores=(
                RootCertificateTrustStoreConstraint(Entity.GOOGLE, ()),
            ),
        )
        existing_root_certificates = collections.OrderedDict([
            ('ANY_KEY', existing_root_certificate),
        ])

        MockSelectedStoreFetcher.parsed_data = {}

        with mock.patch.object(
            FetcherRootCertificateStore,
            'get_root_certificate_store_updaters',
            return_value={Entity.GOOGLE: MockSelectedStoreFetcher},
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            selected_fetcher = (
                trust_stores_module._get_selected_trust_store_fetcher_class(  # pylint: disable=protected-access
                    Entity.GOOGLE
                )
            )
            merged_data = selected_fetcher.from_current_data()

        self.assertEqual(merged_data.parsed_data, [])

    def test_selected_store_duplicate_owner_entries_raise_error(self):
        root_certificate_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())
        first_microsoft_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['first.example'],
            ),
        )
        second_microsoft_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['second.example'],
            ),
        )
        current_google_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['google.example'],
            ),
        )
        existing_root_certificate = RootCertificateParams(
            certificate=root_certificate_pem_lines,
            trust_stores=(
                RootCertificateTrustStoreConstraint(Entity.MICROSOFT, first_microsoft_constraints),
                RootCertificateTrustStoreConstraint(Entity.MICROSOFT, second_microsoft_constraints),
            ),
        )
        existing_root_certificates = collections.OrderedDict([
            ('ANY_KEY', existing_root_certificate),
        ])

        MockSelectedStoreFetcher.parsed_data = {
            root_certificate_pem_lines: current_google_constraints,
        }

        with mock.patch.object(
            FetcherRootCertificateStore,
            'get_root_certificate_store_updaters',
            return_value={Entity.GOOGLE: MockSelectedStoreFetcher},
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            selected_fetcher = (
                trust_stores_module._get_selected_trust_store_fetcher_class(  # pylint: disable=protected-access
                    Entity.GOOGLE
                )
            )
            with self.assertRaisesRegex(ValueError, r'duplicate trust-store owner MICROSOFT'):
                selected_fetcher.from_current_data()

    def test_selected_store_sorts_new_certificates_by_identifier(self):
        first_pem_lines = tuple(self.public_key_x509_lets_encrypt.pem.splitlines())
        second_pem_lines = tuple(self.public_key_x509_snakeoil_ca.pem.splitlines())

        first_identifier = RootCertificateParams(certificate=first_pem_lines).identifier
        second_identifier = RootCertificateParams(certificate=second_pem_lines).identifier

        MockSelectedStoreFetcher.parsed_data = {
            second_pem_lines: (),
            first_pem_lines: (),
        }

        with mock.patch.object(
            FetcherRootCertificateStore,
            'get_root_certificate_store_updaters',
            return_value={Entity.GOOGLE: MockSelectedStoreFetcher},
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=collections.OrderedDict(),
        ):
            selected_fetcher = (
                trust_stores_module._get_selected_trust_store_fetcher_class(  # pylint: disable=protected-access
                    Entity.GOOGLE
                )
            )
            merged_data = selected_fetcher.from_current_data()

        self.assertEqual(
            [root_certificate.identifier for root_certificate in merged_data.parsed_data],
            sorted([first_identifier, second_identifier]),
        )


class TestUpdaterRootCertificateTrustStoreMain(TestRootCertificateBase):
    @staticmethod
    def test_main_uses_default_trust_store():
        updater_mock = mock.Mock()
        with mock.patch.object(
                trust_stores_module,
                'UpdaterRootCertificateTrustStore',
                return_value=updater_mock) as updater_class_mock, mock.patch('sys.argv', ['trust_stores.py']):
            main()

        updater_class_mock.assert_called_once_with(trust_store_owner=None)
        updater_mock.assert_called_once_with()

    @staticmethod
    def test_main_uses_selected_trust_store():
        updater_mock = mock.Mock()
        with mock.patch.object(
                trust_stores_module,
                'UpdaterRootCertificateTrustStore',
                return_value=updater_mock) as updater_class_mock, mock.patch(
                    'sys.argv', ['trust_stores.py', '--trust-store', 'google']
                ):
            main()

        updater_class_mock.assert_called_once_with(trust_store_owner=Entity.GOOGLE)
        updater_mock.assert_called_once_with()

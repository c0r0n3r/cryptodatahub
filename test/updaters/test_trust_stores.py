# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

import csv
import datetime
import io
import os
import tarfile

from test.common.classes import TestClasses


from updaters.common import HttpFetcher, UpdaterBase
from updaters.trust_stores import (
    FetcherRootCertificateStore,
    FetcherRootCertificateStoreApple,
    FetcherRootCertificateStoreGoogle,
    FetcherRootCertificateStoreMicrosoft,
    FetcherRootCertificateStoreMozilla,
)

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.stores import (
    CertificateTrustConstraint,
    RootCertificateBase,
    RootCertificateParams,
    RootCertificateTrustConstraintAction,
)


class TestRootCertificateBase(TestClasses.TestKeyBase):
    def setUp(self):
        super().setUp()

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
            sha2_256_fingerprint = public_key.fingerprints[Hash.SHA2_256].replace(':', '')
            dict_writer.writerow(dict(options[i], **{'SHA-256 Fingerprint': sha2_256_fingerprint}))

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
    def _get_mock_data_google(public_keys=()):
        mock_data = io.BytesIO()

        with tarfile.open(fileobj=mock_data, mode='w:gz') as tar:
            for public_key in public_keys:
                content = public_key.pem.encode('ascii')
                tarinfo = tarfile.TarInfo(public_key.fingerprints[Hash.SHA2_256])
                tarinfo.size = len(content)
                tar.addfile(tarinfo, io.BytesIO(content))

        return mock_data.getvalue()


class TestUpdaterRootCertificateStoreGoogle(TestRootCertificateBase):
    def test_parse_empty(self):
        with mock.patch.object(HttpFetcher, '__call__', return_value=self._get_mock_data_google()):
            root_certificate_store = FetcherRootCertificateStoreGoogle.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')
        mock_data = self._get_mock_data_google([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreGoogle.from_current_data()
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
        mock_data_crt_sh = public_key_x509.pem.encode('ascii')
        with mock.patch.object(HttpFetcher, '__call__', side_effect=[mock_data_apple, mock_data_crt_sh]):
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
        mock_data_crt_sh = public_key_x509.pem.encode('ascii')

        with mock.patch.object(HttpFetcher, '__call__', side_effect=[mock_data_microsoft, mock_data_crt_sh]):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509.pem.splitlines()): (),
        })

    def test_parse_status_disabled(self):
        mock_data = self._get_mock_data_microsoft(
            [self.public_key_x509_snakeoil_ca, self.public_key_x509_lets_encrypt],
            [{}, {'Microsoft Status': 'Disabled'}],
        )
        mock_data = [
            mock_data,
            self.public_key_x509_snakeoil_ca.pem.encode('ascii'),
            self.public_key_x509_snakeoil_ca.pem.encode('ascii'),
        ]

        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(self.public_key_x509_snakeoil_ca.pem.splitlines()): (),
        })

    def test_parse_status_not_before(self):
        mock_data = self._get_mock_data_microsoft(
            [self.public_key_x509_snakeoil_ca, self.public_key_x509_lets_encrypt],
            [{}, {'Microsoft Status': 'NotBefore', 'Valid From [GMT]': '1970 Jan 01'}]
        )
        mock_data = [
            mock_data,
            self.public_key_x509_snakeoil_ca.pem.encode('ascii'),
        ]

        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMicrosoft.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 2)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(self.public_key_x509_snakeoil_ca.pem.splitlines()): (),
            tuple(self.public_key_x509_lets_encrypt.pem.splitlines()): (
                CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    date=datetime.datetime(1970, 1, 1, 0, 0),
                ),
            ),
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
        http_fetcher_results = [
            self._get_mock_data_mozilla(),
            self._get_mock_data_google(),
            self._get_mock_data_microsoft(),
            self._get_mock_data_apple(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 0)

    def test_parse_single_item_in_store(self):
        mock_data_mozilla = self._get_mock_data_mozilla([self.public_key_x509_lets_encrypt])
        mock_data_microsoft = self._get_mock_data_microsoft([self.public_key_x509_snakeoil_ca])
        http_fetcher_results = [
            mock_data_mozilla,
            self._get_mock_data_google(),
            mock_data_microsoft,
            self.public_key_x509_snakeoil_ca.pem.encode('ascii'),
            self._get_mock_data_apple(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 2)
        for root_certificate_param in fetched_data.parsed_data:
            trust_stores = root_certificate_param.trust_stores
            self.assertEqual(len(trust_stores), 1)

    def test_parse_multiple_item_in_store(self):
        mock_data_mozilla = self._get_mock_data_mozilla([
            self.public_key_x509_lets_encrypt,
            self.public_key_x509_snakeoil_ca,
        ])
        mock_data_microsoft = self._get_mock_data_microsoft([
            self.public_key_x509_lets_encrypt,
            self.public_key_x509_snakeoil_ca
        ])
        http_fetcher_results = [
            mock_data_mozilla,
            self._get_mock_data_google(),
            mock_data_microsoft,
            self.public_key_x509_snakeoil_ca.pem.encode('ascii'),
            self._get_mock_data_apple(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 2)
        for root_certificate_param in fetched_data.parsed_data:
            trust_stores = root_certificate_param.trust_stores
            self.assertEqual(len(trust_stores), 2)
        for root_certificate_param in fetched_data.parsed_data:
            trust_stores = root_certificate_param.trust_stores
            for trust_store in trust_stores:
                constraints = trust_store.constraints
                self.assertEqual(len(constraints), 0)

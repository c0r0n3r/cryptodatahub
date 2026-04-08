# -*- coding: utf-8 -*-

from unittest import mock

import argparse
import base64
import collections
import csv
import datetime
import io
import json
import os

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.entity import Entity
from cryptodatahub.common.fetcher import (
    FetcherRootCertificateStore,
    FetcherRootCertificateStoreApple,
    FetcherRootCertificateStoreGoogle,
    FetcherRootCertificateStoreMicrosoft,
    FetcherRootCertificateStoreMozilla,
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


class TestUpdaterRootCertificateStoreGoogle(TestRootCertificateBase):
    def test_parse_empty(self):
        with mock.patch.object(HttpFetcher, '__call__', side_effect=self._get_mock_data_google()):
            root_certificate_store = FetcherRootCertificateStoreGoogle.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509 = self._get_public_key_x509('snakeoil_ca_cert')
        mock_data = self._get_mock_data_google([public_key_x509])
        with mock.patch.object(HttpFetcher, '__call__', side_effect=mock_data):
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
        mock_data_google = self._get_mock_data_google()
        http_fetcher_results = [
            self._get_mock_data_mozilla(),
            mock_data_google[0],
            mock_data_google[1],
            self._get_mock_data_microsoft(),
            self._get_mock_data_apple(),
        ]
        with mock.patch.object(HttpFetcher, '__call__', side_effect=http_fetcher_results):
            fetched_data = FetcherRootCertificateStore.from_current_data()

        self.assertEqual(len(fetched_data.parsed_data), 0)

    def test_parse_single_item_in_store(self):
        mock_data_mozilla = self._get_mock_data_mozilla([self.public_key_x509_lets_encrypt])
        mock_data_google = self._get_mock_data_google()
        mock_data_microsoft = self._get_mock_data_microsoft([self.public_key_x509_snakeoil_ca])
        http_fetcher_results = [
            mock_data_mozilla,
            mock_data_google[0],
            mock_data_google[1],
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
        mock_data_google = self._get_mock_data_google()
        mock_data_microsoft = self._get_mock_data_microsoft([
            self.public_key_x509_lets_encrypt,
            self.public_key_x509_snakeoil_ca
        ])
        http_fetcher_results = [
            mock_data_mozilla,
            mock_data_google[0],
            mock_data_google[1],
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
                        RootCertificateTrustStoreConstraint(Entity.GOOGLE, ()),
                    ),
                ),
            ),
        ])

        current_google_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['example.com'],
            ),
        )

        class CurrentGoogleStore:
            parsed_data = {
                root_certificate_pem_lines: current_google_constraints,
            }

        with mock.patch.object(
            FetcherRootCertificateStoreGoogle,
            'from_current_data',
            return_value=CurrentGoogleStore(),
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            updater = UpdaterRootCertificateTrustStore(Entity.GOOGLE)
            merged_data = updater.fetcher_class.from_current_data()

        self.assertEqual(len(merged_data.parsed_data), 1)
        merged_root_certificate = merged_data.parsed_data[0]
        self.assertEqual(tuple(merged_root_certificate.certificate.pem.splitlines()), root_certificate_pem_lines)
        self.assertEqual(len(merged_root_certificate.trust_stores), 2)
        self.assertEqual(merged_root_certificate.get_constraints_by_owner(Entity.GOOGLE), current_google_constraints)

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
        current_google_constraints = (
            CertificateTrustConstraint(
                action=RootCertificateTrustConstraintAction.DISTRUST,
                domains=['example.com'],
            ),
        )

        class CurrentGoogleStore:
            parsed_data = {
                existing_root_certificate_pem_lines: current_google_constraints,
                new_root_certificate_pem_lines: (),
            }

        with mock.patch.object(
            FetcherRootCertificateStoreGoogle,
            'from_current_data',
            return_value=CurrentGoogleStore(),
        ), mock.patch.object(
            RootCertificate,
            'get_json_records',
            return_value=existing_root_certificates,
        ):
            updater = UpdaterRootCertificateTrustStore(Entity.GOOGLE)
            merged_data = updater.fetcher_class.from_current_data()

        self.assertEqual(len(merged_data.parsed_data), 2)

        merged_by_certificate = {
            tuple(root_certificate.certificate.pem.splitlines()): root_certificate
            for root_certificate in merged_data.parsed_data
        }

        existing_root_certificate = merged_by_certificate[existing_root_certificate_pem_lines]
        self.assertEqual(
            existing_root_certificate.get_constraints_by_owner(Entity.GOOGLE),
            current_google_constraints,
        )
        self.assertEqual(
            existing_root_certificate.get_constraints_by_owner(Entity.MOZILLA),
            (),
        )

        new_root_certificate = merged_by_certificate[new_root_certificate_pem_lines]
        self.assertEqual(new_root_certificate.get_constraints_by_owner(Entity.GOOGLE), ())


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

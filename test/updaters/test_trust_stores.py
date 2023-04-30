# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

import datetime
import os

from test.common.classes import TestClasses

from updaters.common import HttpFetcher
from updaters.trust_stores import (
    FetcherRootCertificateStoreMozilla,
    UpdaterRootCertificateTrustStore,
)

from cryptodatahub.common.stores import (
    CertificateTrustConstraint,
    RootCertificateBase,
    RootCertificateParams,
    RootCertificateTrustConstraintAction,
)
from cryptodatahub.common.types import CryptoDataEnumBase


class TestUpdaterRootCertificateStoreMozilla(TestClasses.TestKeyBase):
    def test_parse_empty(self):
        mock_data = b'"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"'
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 0)

    def test_parse_pem(self):
        public_key_x509_pem = self._get_public_key_pem('letsencrypt_isrg_root_x1')

        mock_data = b'\n'.join([
            b'"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"',
            ','.join([
                '"\'{}\'"'.format(public_key_x509_pem), '""', '""'
            ]).encode('ascii')
        ])
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509_pem.splitlines()): (),
        })

    def test_parse_constraint_date(self):
        public_key_x509_pem = self._get_public_key_pem('letsencrypt_isrg_root_x1')

        mock_data = b'\n'.join([
            b'"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"',
            ','.join([
                '"\'{}\'"'.format(public_key_x509_pem), '"1970.01.01"', '""'
            ]).encode('ascii')
        ])
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509_pem.splitlines()): (
                CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    date=datetime.datetime(1970, 1, 1),
                ),
            )
        })

    def test_parse_constraint_domains(self):
        public_key_x509_pem = self._get_public_key_pem('letsencrypt_isrg_root_x1')

        mock_data = b'\n'.join([
            b'"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"',
            ','.join([
                '"\'{}\'"'.format(public_key_x509_pem), '""', '"domain"'
            ]).encode('ascii')
        ])
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            root_certificate_store = FetcherRootCertificateStoreMozilla.from_current_data()
        self.assertEqual(len(root_certificate_store.parsed_data), 1)
        self.assertEqual(root_certificate_store.parsed_data, {
            tuple(public_key_x509_pem.splitlines()): (
                CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    domains=["domain"],
                ),
            )
        })


class TestFetcherRootCertificateStore(TestClasses.TestKeyBase):
    def test_parse_empty(self):
        self.fs.create_file(str(CryptoDataEnumBase.get_json_path(RootCertificateParams)), contents='{}')
        mock_data = b'"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"'
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            UpdaterRootCertificateTrustStore()()
            root_certificate_class = RootCertificateBase(
                'RootCertificate', RootCertificateBase.get_json_records(RootCertificateParams)
            )

        self.assertEqual(len(root_certificate_class), 0)

    def test_parse_single(self):
        self.fs.create_file(str(CryptoDataEnumBase.get_json_path(RootCertificateParams)), contents='{}')
        public_key_x509_pem = self._get_public_key_pem('letsencrypt_isrg_root_x1')

        mock_data = os.linesep.join([
            '"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"',
            '"\'{}\'","",""'.format(public_key_x509_pem),
        ]).encode('ascii')
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            UpdaterRootCertificateTrustStore()()
            root_certificate_class = RootCertificateBase(
                'RootCertificate', RootCertificateBase.get_json_records(RootCertificateParams)
            )

        for root_certificate in root_certificate_class:
            trust_stores = root_certificate.value.trust_stores
            self.assertEqual(len(trust_stores), 1)

    def test_parse_multiple(self):
        self.fs.create_file(str(CryptoDataEnumBase.get_json_path(RootCertificateParams)), contents='{}')
        public_key_x509_lets_encrypt = self._get_public_key_pem('letsencrypt_isrg_root_x1')
        public_key_x509_snakeoil_ca = self._get_public_key_pem('snakeoil_ca_cert')

        mock_data = os.linesep.join([
            '"PEM","Distrust for TLS After Date","Mozilla Applied Constraints"',
            '"\'{}\'","",""'.format(public_key_x509_lets_encrypt),
            '"\'{}\'","",""'.format(public_key_x509_snakeoil_ca),
        ]).encode('ascii')
        with mock.patch.object(HttpFetcher, '__call__', return_value=mock_data):
            UpdaterRootCertificateTrustStore()()
            root_certificate_class = RootCertificateBase(
                'RootCertificate', RootCertificateBase.get_json_records(RootCertificateParams)
            )

        for root_certificate in root_certificate_class:
            trust_stores = root_certificate.value.trust_stores
            self.assertEqual(len(trust_stores), 1)
        for root_certificate in root_certificate_class:
            trust_stores = root_certificate.value.trust_stores
            for trust_store in trust_stores:
                constraints = trust_store.constraints
                self.assertEqual(len(constraints), 0)

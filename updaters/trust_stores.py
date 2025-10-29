#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import datetime
import io
import tarfile

import attr
import bs4

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTrustConstraint,
    RootCertificate,
    RootCertificateParams,
    RootCertificateTrustStoreConstraint,
    RootCertificateTrustConstraintAction,
)
from cryptodatahub.common.types import Base64Data, CryptoDataParamsBase

from updaters.common import CertificatePemFetcher, FetcherBase, FetcherCsvBase, HttpFetcher, UpdaterBase


@attr.s
class RootCertificateStore(CryptoDataParamsBase):
    certificates = attr.ib(
        default={},
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(Base64Data),
            value_validator=attr.validators.instance_of(RootCertificateTrustConstraintAction)
        )
    )


class FetcherRootCertificateStoreGoogle(FetcherBase):
    @classmethod
    def _get_current_data(cls):
        data = HttpFetcher()(
            'https://android.googlesource.com/platform/system/ca-certificates/+archive/refs/heads/master/files.tar.gz'
        )
        with tarfile.open(fileobj=io.BytesIO(data), mode='r') as tar:
            for member in tar.getmembers():
                yield tar.extractfile(member).read().decode('ascii')

    @classmethod
    def _transform_data(cls, current_data):
        certificates = {}
        for root_certificate_pem in current_data:
            root_certificate_pem_lines = root_certificate_pem.splitlines()
            root_certificate_pem_lines = root_certificate_pem_lines[
                :root_certificate_pem_lines.index('-----END CERTIFICATE-----') + 1
            ]

            certificates[tuple(root_certificate_pem_lines)] = tuple()

        return certificates


class FetcherRootCertificateStoreApple(FetcherBase):
    FIELDS = (
        'Certificate name',
        'Issued by',
        'Type',
        'Key size',
        'Sig alg',
        'Serial number',
        'Expires',
        'EV policy',
        'Fingerprint (SHA-256)',
    )

    @classmethod
    def _get_current_data(cls):
        response = HttpFetcher()('https://support.apple.com/en-us/HT213080')
        page = bs4.BeautifulSoup(response.decode('utf-8'), 'html.parser')
        trusted_cas = page.find("h2", {"id": "trusted"})
        return [
            dict(zip(cls.FIELDS, map(lambda value: value.text.strip(), row.find_all('td'))))
            for row in trusted_cas.find_next('tbody').find_all('tr')[1:]
        ]

    @classmethod
    def _transform_data(cls, current_data):
        certificate_pem_fetcher = CertificatePemFetcher()
        certificates = {}
        for row in current_data:
            sha2_256_fingerprint = row['Fingerprint (SHA-256)'].replace(' ', '')
            root_certificate_pem = certificate_pem_fetcher(sha2_256_fingerprint)
            certificates[tuple(root_certificate_pem.splitlines())] = ()

        return certificates


class FetcherRootCertificateStoreMicrosoft(FetcherCsvBase):
    CSV_FIELDS = (
        'Microsoft Status',
        'CA Owner',
        'CA Common Name or Certificate Name',
        'SHA-1 Fingerprint',
        'SHA-256 Fingerprint',
        'Microsoft EKUs',
        'Valid From [GMT]',
        'Valid To [GMT]',
        'Public Key Algorithm',
        'Signature Hash Algorithm',
    )

    @classmethod
    def _get_csv_url(cls):
        return 'https://ccadb-public.secure.force.com/microsoft/IncludedCACertificateReportForMSFTCSV'

    @classmethod
    def _get_csv_fields(cls):
        return cls.CSV_FIELDS

    @classmethod
    def _transform_data(cls, current_data):
        certificate_pem_fetcher = CertificatePemFetcher()
        certificates = {}

        for row in current_data:
            status = row['Microsoft Status']

            if status == 'Disabled':
                continue

            constraints = []
            if status == 'NotBefore':
                constraint = CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    date=datetime.datetime.strptime(row['Valid From [GMT]'], '%Y %b %d'),
                )
                constraints.append(constraint)

            sha2_256_fingerprint = row['SHA-256 Fingerprint']
            root_certificate_pem = certificate_pem_fetcher(sha2_256_fingerprint)

            certificates[tuple(root_certificate_pem.splitlines())] = tuple(constraints)

        return certificates


class FetcherRootCertificateStoreMozilla(FetcherCsvBase):
    CSV_FIELDS = ('PEM', 'Distrust for TLS After Date', 'Mozilla Applied Constraints')

    @classmethod
    def _get_csv_url(cls):
        return \
            'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites'

    @classmethod
    def _get_csv_fields(cls):
        return cls.CSV_FIELDS

    @classmethod
    def _transform_data(cls, current_data):
        certificates = {}

        for row in current_data:
            constraints = []

            distrust_after = row['Distrust for TLS After Date']
            if distrust_after:
                constraint = CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    date=datetime.datetime.strptime(distrust_after, '%Y.%m.%d'),
                )
                constraints.append(constraint)

            domain = row['Mozilla Applied Constraints']
            if domain:
                constraint = CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    domains=[domain],
                )
                constraints.append(constraint)

            root_certificate_pem_lines = tuple(row['PEM'].strip('\'').splitlines())
            certificates[root_certificate_pem_lines] = tuple(constraints)

        return certificates


class FetcherRootCertificateStore(FetcherBase):
    _ROOT_CERTIFICATE_STORE_UPDATERS = collections.OrderedDict([
        (Entity.MOZILLA, FetcherRootCertificateStoreMozilla),
        (Entity.GOOGLE, FetcherRootCertificateStoreGoogle),
        (Entity.MICROSOFT, FetcherRootCertificateStoreMicrosoft),
        (Entity.APPLE, FetcherRootCertificateStoreApple),
    ])

    @classmethod
    def _get_current_data(cls):
        return collections.OrderedDict([
            (store_owner, store_fetcher_class.from_current_data())
            for store_owner, store_fetcher_class in cls._ROOT_CERTIFICATE_STORE_UPDATERS.items()
        ])

    @classmethod
    def _transform_data(cls, current_data):
        root_certificates = {}

        for store_owner, root_store in current_data.items():
            for certificate_data, constraints in root_store.parsed_data.items():
                if certificate_data in root_certificates:
                    merged_constraints = root_certificates[certificate_data]
                else:
                    merged_constraints = []
                    root_certificates[certificate_data] = merged_constraints

                merged_constraints.append(RootCertificateTrustStoreConstraint(store_owner, constraints))

        return [
            RootCertificateParams(*item)
            for item in root_certificates.items()
        ]


class UpdaterRootCertificateTrustStore(UpdaterBase):
    def __init__(self):
        super().__init__(  # pragma: no cover
            fetcher_class=FetcherRootCertificateStore,
            enum_class=RootCertificate,
            enum_param_class=RootCertificateParams,
        )


def main():
    UpdaterRootCertificateTrustStore()()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

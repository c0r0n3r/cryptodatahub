#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import datetime

import attr

import six

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTrustConstraint,
    RootCertificate,
    RootCertificateParams,
    RootCertificateTrustStoreConstraint,
    RootCertificateTrustConstraintAction,
)
from cryptodatahub.common.types import Base64Data, CryptoDataParamsBase

from updaters.common import FetcherBase, FetcherCsvBase, HttpFetcher, UpdaterBase


@attr.s
class RootCertificateStore(CryptoDataParamsBase):
    certificates = attr.ib(
        default={},
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(Base64Data),
            value_validator=attr.validators.instance_of(RootCertificateTrustConstraintAction)
        )
    )


class FetcherRootCertificateStoreBase(FetcherCsvBase):
    @classmethod
    def _get_root_certificate_class(cls):
        return RootCertificate

    @classmethod
    def _get_certificate_pem(cls, sha2_256_fingerprint):
        try:
            root_certificate_class = cls._get_root_certificate_class()
            return root_certificate_class.get_item_by_sha2_256_fingerprint(
                sha2_256_fingerprint
            ).value.certificate.pem
        except KeyError:
            data = HttpFetcher(
                connect_timeout=5, read_timeout=30, retry=10,
            )(
                'https://crt.sh/?d={}'.format(sha2_256_fingerprint),
            )

            return six.ensure_str(data).strip()

    @classmethod
    def _get_csv_url(cls):
        raise NotImplementedError()

    @classmethod
    def _get_csv_fields(cls):
        raise NotImplementedError()

    @classmethod
    def _transform_data(cls, current_data):
        raise NotImplementedError()


class FetcherRootCertificateStoreMicrosoft(FetcherRootCertificateStoreBase):
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
            root_certificate_pem = cls._get_certificate_pem(sha2_256_fingerprint)

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
        (Entity.MICROSOFT, FetcherRootCertificateStoreMicrosoft),
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
        super(UpdaterRootCertificateTrustStore, self).__init__(  # pragma: no cover
            fetcher_class=FetcherRootCertificateStore,
            enum_class=RootCertificate,
            enum_param_class=RootCertificateParams,
        )


def main():
    UpdaterRootCertificateTrustStore()()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

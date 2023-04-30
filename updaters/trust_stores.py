#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import datetime

import attr

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTrustConstraint,
    RootCertificate,
    RootCertificateParams,
    RootCertificateTrustStoreConstraint,
    RootCertificateTrustConstraintAction,
)
from cryptodatahub.common.types import Base64Data, CryptoDataParamsBase

from updaters.common import FetcherBase, FetcherCsvBase, UpdaterBase


@attr.s
class RootCertificateStore(CryptoDataParamsBase):
    certificates = attr.ib(
        default={},
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(Base64Data),
            value_validator=attr.validators.instance_of(RootCertificateTrustConstraintAction)
        )
    )


class FetcherRootCertificateStoreMozilla(FetcherCsvBase):
    @classmethod
    def _get_csv_url(cls):
        return \
            'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites'

    @classmethod
    def _get_csv_fields(cls):
        return ('PEM', 'Distrust for TLS After Date', 'Mozilla Applied Constraints')

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

            root_certificate_pem_lines = tuple(row['PEM'][1:-1].splitlines())
            certificates[root_certificate_pem_lines] = tuple(constraints)

        return certificates


class FetcherRootCertificateStore(FetcherBase):
    _ROOT_CERTIFICATE_STORE_UPDATERS = collections.OrderedDict([
        (Entity.MOZILLA, FetcherRootCertificateStoreMozilla),
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
                merged_constraints = []
                root_certificates[certificate_data] = merged_constraints

                merged_constraints.append(RootCertificateTrustStoreConstraint(store_owner, constraints))

        return [
            RootCertificateParams(*item)
            for item in root_certificates.items()
        ]


class UpdaterRootCertificateTrustStore(UpdaterBase):
    def __init__(self):
        super(UpdaterRootCertificateTrustStore, self).__init__(
            fetcher_class=FetcherRootCertificateStore,
            enum_class=RootCertificate,
            enum_param_class=RootCertificateParams,
        )


def main():
    UpdaterRootCertificateTrustStore()()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

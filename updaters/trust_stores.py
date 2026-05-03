#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import collections

import attr

from cryptodatahub.common.entity import Entity, EntityRole
from cryptodatahub.common.stores import (
    RootCertificate,
    RootCertificateParams,
    RootCertificateTrustConstraintAction,
    RootCertificateTrustStoreConstraint,
)
from cryptodatahub.common.types import Base64Data, CryptoDataParamsBase

from cryptodatahub.common.fetcher import FetcherBase, FetcherRootCertificateStore

from updaters.common import UpdaterBase


@attr.s
class RootCertificateStore(CryptoDataParamsBase):
    certificates = attr.ib(
        default={},
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(Base64Data),
            value_validator=attr.validators.instance_of(RootCertificateTrustConstraintAction)
        )
    )


def _get_trust_store_owner_choices():
    return collections.OrderedDict([
        ('all', None),
    ] + [
        (trust_store_owner.name.lower(), trust_store_owner)
        for trust_store_owner in Entity.get_items_by_role(EntityRole.CA_TRUST_STORE_OWNER)
    ])


def _parse_trust_store_owner(value):
    normalized_value = value.lower()
    trust_store_owner_choices = _get_trust_store_owner_choices()

    try:
        return trust_store_owner_choices[normalized_value]
    except KeyError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid trust store {value!r}; expected one of: {', '.join(trust_store_owner_choices.keys())}"
        ) from exc


def _get_selected_trust_store_fetcher_class(trust_store_owner):
    store_fetcher_class = FetcherRootCertificateStore.get_root_certificate_store_updaters()[trust_store_owner]

    class FetcherRootCertificateStoreSelected(FetcherBase):
        @classmethod
        def _get_current_data(cls):
            current_root_store = store_fetcher_class.from_current_data()
            existing_root_certificates = collections.OrderedDict([
                (root_certificate.identifier, root_certificate)
                for root_certificate in RootCertificate.get_json_records(RootCertificateParams).values()
            ])

            current_root_certificates = collections.OrderedDict()
            for certificate_data, constraints in current_root_store.parsed_data.items():
                current_root_certificate = RootCertificateParams(
                    certificate=certificate_data,
                    trust_stores=(RootCertificateTrustStoreConstraint(trust_store_owner, constraints),),
                )
                current_root_certificates[current_root_certificate.identifier] = current_root_certificate

            merged_root_certificates = collections.OrderedDict()
            for identifier, existing_root_certificate in existing_root_certificates.items():
                current_root_certificate = current_root_certificates.pop(identifier, None)
                selected_trust_store_constraints = None
                if current_root_certificate is not None:
                    selected_trust_store_constraints = current_root_certificate.trust_stores[0].constraints

                owner_constraints = collections.OrderedDict([
                    (trust_store.owner, trust_store.constraints)
                    for trust_store in existing_root_certificate.trust_stores
                ])

                if selected_trust_store_constraints is None:
                    owner_constraints.pop(trust_store_owner, None)
                else:
                    owner_constraints[trust_store_owner] = selected_trust_store_constraints

                merged_trust_stores = [
                    RootCertificateTrustStoreConstraint(owner, constraints)
                    for owner, constraints in owner_constraints.items()
                ]

                if merged_trust_stores:
                    merged_root_certificates[identifier] = RootCertificateParams(
                        certificate=existing_root_certificate.certificate,
                        trust_stores=tuple(merged_trust_stores),
                    )

            for identifier in sorted(current_root_certificates.keys()):
                merged_root_certificates[identifier] = current_root_certificates[identifier]

            return list(merged_root_certificates.values())

        @classmethod
        def _transform_data(cls, current_data):
            return current_data

    return FetcherRootCertificateStoreSelected


class UpdaterRootCertificateTrustStore(UpdaterBase):
    def __init__(self, trust_store_owner=None):
        if trust_store_owner is None:
            fetcher_class = FetcherRootCertificateStore
        else:
            fetcher_class = _get_selected_trust_store_fetcher_class(trust_store_owner)

        super().__init__(  # pragma: no cover
            fetcher_class=fetcher_class,
            enum_class=RootCertificate,
            enum_param_class=RootCertificateParams,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--trust-store',
        default='all',
        type=_parse_trust_store_owner,
        help='trust store to update; use all to update every trust store (default: all)',
    )
    args = parser.parse_args()

    UpdaterRootCertificateTrustStore(trust_store_owner=args.trust_store)()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

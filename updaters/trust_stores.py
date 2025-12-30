#!/usr/bin/env python
# -*- coding: utf-8 -*-

import attr

from cryptodatahub.common.stores import (
    RootCertificate,
    RootCertificateParams,
    RootCertificateTrustConstraintAction,
)
from cryptodatahub.common.types import Base64Data, CryptoDataParamsBase

from cryptodatahub.common.fetcher import FetcherRootCertificateStore

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

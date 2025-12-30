#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptodatahub.common.stores import CertificateTransparencyLog, CertificateTransparencyLogParams

from cryptodatahub.common.fetcher import FetcherCertificateTransparencyLogs

from updaters.common import UpdaterBase


class UpdaterCertificateTransparencyLogs(UpdaterBase):
    def __init__(self):
        super().__init__(
            FetcherCertificateTransparencyLogs,
            CertificateTransparencyLog,
            CertificateTransparencyLogParams,
        )


def main():
    UpdaterCertificateTransparencyLogs()()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

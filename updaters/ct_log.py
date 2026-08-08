#!/usr/bin/env python
# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import collections

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

    def _merge(self, existing_data, current_items_by_identifier):
        current_values_by_log_id = collections.OrderedDict()
        for item in current_items_by_identifier.values():
            current_value = item._asdict()
            current_values_by_log_id[current_value['log_id']] = current_value

        merged_data = collections.OrderedDict()
        existing_log_ids = set()
        for identifier, value in existing_data.items():
            existing_log_ids.add(value['log_id'])
            current_value = current_values_by_log_id.get(value['log_id'])
            if current_value is not None:
                merged_value = collections.OrderedDict(value)
                merged_value['trust_stores'] = current_value['trust_stores']
                merged_data[identifier] = merged_value
            else:
                merged_data[identifier] = value
        for identifier in sorted(current_items_by_identifier):
            current_value = current_items_by_identifier[identifier]._asdict()
            if current_value['log_id'] not in existing_log_ids:
                merged_data[identifier] = current_value

        return collections.OrderedDict(sorted(merged_data.items(), key=self.sort_key))


def main():
    UpdaterCertificateTransparencyLogs()()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

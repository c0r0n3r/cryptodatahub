#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import json

import attr
import urllib3

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import CertificateTransparencyLog, CertificateTransparencyLogParams
from cryptodatahub.common.utils import name_to_enum_item_name

from updaters.common import FetcherBase, UpdaterBase


@attr.s
class FetcherCertificateTransparencyLogs(FetcherBase):
    _CT_LOGS_ALL_JSON_URL = 'https://www.gstatic.com/ct/log_list/v3/all_logs_list.json'
    _CT_LOG_OPERATOR_NAME_GOOGLE_NAME = {
        'Up In The Air Consulting': 'Filippo Valsorda',
        'Wang Shengnan': 'GDCA',
    }

    @classmethod
    def _get_current_data(cls):
        http = urllib3.PoolManager()
        response = http.request('GET', cls._CT_LOGS_ALL_JSON_URL, preload_content=False)
        response.release_conn()

        return json.loads(response.data, object_pairs_hook=collections.OrderedDict)

    @classmethod
    def _transform_data(cls, current_data):
        transformed_logs = []

        for operator in current_data['operators']:
            logs = operator.pop('logs')
            for log in logs:
                if 'state' in log:
                    state = log.pop('state')
                    state_type = list(state)[0]
                    state_args = collections.OrderedDict([('state_type', state_type)])
                    state_args.update(state[state_type])
                    state_args.pop('final_tree_head', None)

                    log.update(collections.OrderedDict([('log_state', state_args)]))

                operator_name = operator['name']
                operator_name = cls._CT_LOG_OPERATOR_NAME_GOOGLE_NAME.get(operator_name, operator_name)
                log['operator'] = Entity[name_to_enum_item_name(operator_name)].name

                transformed_logs.append(CertificateTransparencyLogParams(**log))

        return transformed_logs


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

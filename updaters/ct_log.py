#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import json
import re

import urllib3

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import CertificateTransparencyLogParams

from updaters.common import UpdaterBase


class UpdaterCertificateTransparencyLogs(UpdaterBase):
    _CT_LOGS_ALL_JSON_URL = 'https://www.gstatic.com/ct/log_list/v3/all_logs_list.json'
    _CT_LOG_OPERATOR_NAME_GOOGLE_NAME = {
        'Up In The Air Consulting': 'Filippo Valsorda',
        'Wang Shengnan': 'GDCA',
    }

    def _get_current_data(self):
        http = urllib3.PoolManager()
        response = http.request('GET', self._CT_LOGS_ALL_JSON_URL, preload_content=False)
        response.release_conn()

        return json.loads(response.data, object_pairs_hook=collections.OrderedDict)

    @staticmethod
    def convert_name(name):
        name = re.sub('\'', '', name.upper())

        name = re.sub('[^A-Z0-9]', '_', name)
        name = re.sub('__', '_', name)

        return name.strip('_')

    @staticmethod
    def convert_description(description):
        name = UpdaterCertificateTransparencyLogs.convert_name(description)

        name = re.sub('([^_])(20[12][0-9][_0-9]*)(H[1-2])?(_LOG)?$', '\\1_\\2\\3\\4', name)

        return name

    def _transform_data(self, current_data):
        transformed_logs = []

        for operator in current_data['operators']:
            logs = operator.pop('logs')
            for log in logs:
                if 'state' in log:
                    state = log.pop('state')
                    state_type = list(state)[0]
                    state_args = collections.OrderedDict([('state_type', state_type)])
                    state_args.update(state[state_type])
                    log.update(collections.OrderedDict([('log_state', state_args)]))

                operator_name = operator['name']
                operator_name = self._CT_LOG_OPERATOR_NAME_GOOGLE_NAME.get(operator_name, operator_name)
                log['operator'] = Entity[self.convert_name(operator_name)].name

                transformed_logs.append(log)

        return collections.OrderedDict([
            (self.convert_description(log['description']), log)
            for log in transformed_logs
        ])

    def _get_param_class(self):
        return CertificateTransparencyLogParams


def main():
    UpdaterCertificateTransparencyLogs().update()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

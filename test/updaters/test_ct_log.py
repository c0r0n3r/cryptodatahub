# -*- coding: utf-8 -*-

import collections
import codecs
import urllib3

try:
    from unittest import mock
except ImportError:
    import mock

import pyfakefs.fake_filesystem_unittest

from updaters.ct_log import UpdaterCertificateTransparencyLogs

from cryptodatahub.common.types import CryptoDataEnumBase
from cryptodatahub.common.stores import CertificateTransparencyLogParams


class TestUpdaterCertificateTransparencyLogs(pyfakefs.fake_filesystem_unittest.TestCase):
    CT_LOG_LIST_JSON_SAMPLE = """
        {
          "operators": [
            {
              "name": "Up In The Air Consulting",
              "email": [
                "filippo@cloudflare.com"
              ],
              "logs": [
                {
                  "description": "description",
                  "log_id": "log_id",
                  "key": "key",
                  "url": "https://log.id/",
                  "mmd": 86400,
                  "state": {
                    "rejected": {
                      "timestamp": "1970-01-01T00:00:00Z"
                    }
                  },
                  "temporal_interval": {
                    "start_inclusive": "1970-01-01T00:00:00Z",
                    "end_exclusive": "1970-01-01T00:00:00Z"
                  }
                }
              ]
            }
          ]
        }
    """
    CT_LOG_LIST_SAMPLE_OBJECT = collections.OrderedDict([(
        'DESCRIPTION',
        collections.OrderedDict([
            ('log_id', 'log_id'),
            ('operator', 'FILIPPO_VALSORDA'),
            ('key', 'key'),
            ('url', 'https://log.id/'),
            ('mmd', 86400),
            ('description', 'description'),
            ('temporal_interval', collections.OrderedDict([
                ('start_inclusive', '1970-01-01T00:00:00Z'),
                ('end_exclusive', '1970-01-01T00:00:00Z'),
            ])),
            ('log_state', collections.OrderedDict([
                ('state_type', 'rejected'),
                ('timestamp', '1970-01-01T00:00:00Z'),
            ])),
        ])
    )])

    def setUp(self):
        self.setUpPyfakefs()

    def test_convert_description(self):
        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('CaMeL CaSe'),
            'CAMEL_CASE'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('S"p+e!c%i/a=l'),
            'S_P_E_C_I_A_L'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('S""p++e!!c%%i//a==l'),
            'S_P_E_C_I_A_L'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('  leading spaces'),
            'LEADING_SPACES'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('trailing spaces  '),
            'TRAILING_SPACES'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Log'),
            'ORGANIZATION_LOG'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Log 2'),
            'ORGANIZATION_LOG_2'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Log 2023'),
            'ORGANIZATION_LOG_2023'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Log 2023 2'),
            'ORGANIZATION_LOG_2023_2'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Log 2023H2'),
            'ORGANIZATION_LOG_2023H2'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Log v1 2023'),
            'ORGANIZATION_LOG_V1_2023'
        )

        self.assertEqual(
            UpdaterCertificateTransparencyLogs.convert_description('Organization Ct Log 2023'),
            'ORGANIZATION_CT_LOG_2023'
        )

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_log_list_parsing(self, mock_request):
        mock_request.return_value = urllib3.response.HTTPResponse(self.CT_LOG_LIST_JSON_SAMPLE)
        current_data = UpdaterCertificateTransparencyLogs().get_current_data()
        self.assertTrue(isinstance(current_data, collections.OrderedDict))
        self.assertEqual(current_data, self.CT_LOG_LIST_SAMPLE_OBJECT)

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_log_list_update(self, mock_request):
        mock_request.return_value = urllib3.response.HTTPResponse(self.CT_LOG_LIST_JSON_SAMPLE)
        json_file_path = str(CryptoDataEnumBase.get_json_path(CertificateTransparencyLogParams))
        self.fs.create_file(json_file_path, contents='{}')

        UpdaterCertificateTransparencyLogs().update()
        with codecs.open(json_file_path, 'r', encoding='ascii') as json_file:
            self.assertEqual(json_file.read(), CryptoDataEnumBase.dump_json(self.CT_LOG_LIST_SAMPLE_OBJECT))

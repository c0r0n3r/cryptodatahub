# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import datetime
import dateutil
import urllib3

try:
    from unittest import mock
except ImportError:
    import mock

import pyfakefs.fake_filesystem_unittest

from cryptodatahub.common.types import CryptoDataEnumBase
from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTransparencyLogParams,
    CertificateTransparencyLogState,
    CertificateTransparencyLogStateType,
    CertificateTransparencyLogTemporalInterval,
    CertificateTransparencyLogTrustStore,
)

from cryptodatahub.common.fetcher import (
    FetcherCertificateTransparencyLogs,
    FetcherCertificateTransparencyLogStoreApple,
    FetcherCertificateTransparencyLogStoreGoogle,
)

from updaters.ct_log import UpdaterCertificateTransparencyLogs


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
                  "log_id": "bG9nX2lk",
                  "key": "a2V5",
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
              ],
              "tiled_logs": [
                {
                  "description": "tiled description",
                  "log_id": "dGlsZWRfaWQ=",
                  "key": "dGlsZWRfa2V5",
                  "mmd": 60,
                  "monitoring_url": "https://tiled.example/monitor/",
                  "submission_url": "https://tiled.example/submit/",
                  "tls_only": true,
                  "state": {
                    "usable": {
                      "timestamp": "1970-01-01T00:00:00Z"
                    }
                  }
                }
              ]
            }
          ]
        }
    """
    _LOG_STATE = CertificateTransparencyLogState(
        state_type=CertificateTransparencyLogStateType.REJECTED,
        timestamp=datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=dateutil.tz.UTC),
    )
    CT_LOG_ITEM_OBJECT = CertificateTransparencyLogParams(
         log_id='bG9nX2lk',
         operator='FILIPPO_VALSORDA',
         key='a2V5',
         url='https://log.id/',
         mmd=86400,
         description='description',
         temporal_interval=CertificateTransparencyLogTemporalInterval(
            start_inclusive=datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=dateutil.tz.UTC),
            end_exclusive=datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=dateutil.tz.UTC),
         ),
         trust_stores=(
            CertificateTransparencyLogTrustStore(owner=Entity.APPLE, log_state=_LOG_STATE),
            CertificateTransparencyLogTrustStore(owner=Entity.GOOGLE, log_state=_LOG_STATE),
         ),
    )
    _TILED_LOG_STATE = CertificateTransparencyLogState(
        state_type=CertificateTransparencyLogStateType.USABLE,
        timestamp=datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=dateutil.tz.UTC),
    )
    CT_TILED_LOG_ITEM_OBJECT = CertificateTransparencyLogParams(
         log_id='dGlsZWRfaWQ=',
         operator='FILIPPO_VALSORDA',
         key='dGlsZWRfa2V5',
         mmd=60,
         description='tiled description',
         trust_stores=(
            CertificateTransparencyLogTrustStore(owner=Entity.APPLE, log_state=_TILED_LOG_STATE),
            CertificateTransparencyLogTrustStore(owner=Entity.GOOGLE, log_state=_TILED_LOG_STATE),
         ),
    )

    def setUp(self):
        self.setUpPyfakefs()

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_log_list_parsing(self, mock_request):
        mock_request.return_value = urllib3.response.HTTPResponse(self.CT_LOG_LIST_JSON_SAMPLE)
        current_data = FetcherCertificateTransparencyLogs.from_current_data()
        self.assertTrue(isinstance(current_data, FetcherCertificateTransparencyLogs))
        parsed_by_log_id = {p.log_id.value: p for p in current_data.parsed_data}
        self.assertEqual(
            parsed_by_log_id[self.CT_LOG_ITEM_OBJECT.log_id.value],
            self.CT_LOG_ITEM_OBJECT,
        )
        self.assertEqual(
            parsed_by_log_id[self.CT_TILED_LOG_ITEM_OBJECT.log_id.value],
            self.CT_TILED_LOG_ITEM_OBJECT,
        )

    def test_get_ct_log_store_updaters(self):
        updaters = FetcherCertificateTransparencyLogs.get_ct_log_store_updaters()
        self.assertEqual(updaters[Entity.GOOGLE], FetcherCertificateTransparencyLogStoreGoogle)
        self.assertEqual(updaters[Entity.APPLE], FetcherCertificateTransparencyLogStoreApple)

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_log_list_update(self, mock_request):
        mock_request.return_value = urllib3.response.HTTPResponse(self.CT_LOG_LIST_JSON_SAMPLE)
        json_file_path = str(CryptoDataEnumBase.get_json_path(CertificateTransparencyLogParams))
        self.fs.create_file(json_file_path, contents='{}')

        UpdaterCertificateTransparencyLogs()()
        with open(json_file_path, 'r', encoding='ascii') as json_file:
            self.assertEqual(
                json_file.read(),
                CryptoDataEnumBase.dump_json({
                    'DESCRIPTION': self.CT_LOG_ITEM_OBJECT._asdict(),
                    'TILED_DESCRIPTION': self.CT_TILED_LOG_ITEM_OBJECT._asdict(),
                }),
            )

# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.tls.client import TlsClient


class TestTlsClient(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return TlsClient

    def test_asdict(self):
        client_dict = TlsClient.FIREFOX_56.value.capabilities._asdict()
        self.assertEqual(
            list(filter(lambda extension_param: extension_param is None, client_dict['extension_params'].values())),
            []
        )

    def test_str(self):
        self.assertEqual(str(TlsClient.FIREFOX_56.value.meta), 'Mozilla Firefox (56 - 72)')

# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.dnssec.algorithm import DnsSecAlgorithm


class TestDnsSecAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return DnsSecAlgorithm

    def test_name(self):
        self.assertEqual(str(DnsSecAlgorithm.RSAMD5.value), 'RSA/MD5')

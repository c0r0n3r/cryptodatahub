# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.dnssec.algorithm import DnsSecAlgorithm, DnsSecDigestType


class TestDnsSecAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return DnsSecAlgorithm

    def test_name(self):
        self.assertEqual(str(DnsSecAlgorithm.RSAMD5.value), 'RSA/MD5')


class TestDnsSecDigestType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return DnsSecDigestType

    def test_name(self):
        self.assertEqual(str(DnsSecDigestType.SHA_256.value), 'SHA-256')

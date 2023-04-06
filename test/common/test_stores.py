# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTransparencyLog,
    CertificateTransparencyLogParams,
    CertificateTransparencyLogUnknown,
)


class TestCertificateTransparencyLog(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return CertificateTransparencyLog

    def test_error_mmd_too_small(self):
        with self.assertRaises(ValueError) as context_manager:
            CertificateTransparencyLogParams(
                operator=Entity.GOOGLE,
                log_id='=',
                key=b'',
                url='',
                mmd=0
            )
        self.assertEqual(context_manager.exception.args, (0, ))

    def test_from_log_id(self):
        self.assertEqual(
            CertificateTransparencyLog.from_log_id('lgbALGkAM6odFF9ZxuJkjQVJ8N+WqrjbkVpw2OzzkKU='),
            CertificateTransparencyLog.AKAMAI_CT_LOG.value
        )
        self.assertEqual(
            CertificateTransparencyLog.from_log_id(bytearray(b'unkown log')),
            CertificateTransparencyLogUnknown(bytearray(b'unkown log'))
        )

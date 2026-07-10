# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestClasses

from cryptodatahub.tls.version import TlsVersion


class TestTlsVersion(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsVersion

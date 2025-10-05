# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.ike.algorithm import IkePayloadType


class TestIkePayloadType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return IkePayloadType

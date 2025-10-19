# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.ike.algorithm import (
    IkePayloadType,
    Ikev2NotifyType,
    Ikev2ExtendedSequenceNumber,
    Ikev2TransformType,
)


class TestIkePayloadType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return IkePayloadType


class TestIkev2NotifyType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2NotifyType


class TestIkev2ExtendedSequenceNumber(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2ExtendedSequenceNumber


class TestIkev2TransformType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return Ikev2TransformType

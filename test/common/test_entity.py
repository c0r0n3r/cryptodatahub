# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.common.entity import Entity


class TestEntity(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Entity

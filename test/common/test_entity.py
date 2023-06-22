# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.common.entity import Entity, Server


class TestEntity(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Entity


class TestServer(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Server

    def test_str(self):
        self.assertEqual(str(Server.HAPROXY.value), 'HAProxy')
        self.assertEqual(str(Server.NGINX.value), 'NGINX (F5)')

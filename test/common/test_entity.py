# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.common.entity import Entity, EntityRole, Server


class TestEntity(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Entity

    def test_get_items_by_role(self):
        trust_store_owners = Entity.get_items_by_role(EntityRole.CA_TRUST_STORE_OWNER)
        self.assertEqual(len(trust_store_owners), 4)
        self.assertEqual(id(trust_store_owners), id(Entity.get_items_by_role(EntityRole.CA_TRUST_STORE_OWNER)))


class TestServer(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return Server

    def test_str(self):
        self.assertEqual(str(Server.HAPROXY.value), 'HAProxy')
        self.assertEqual(str(Server.NGINX.value), 'NGINX (F5)')

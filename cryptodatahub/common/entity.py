# -*- coding: utf-8 -*-

import enum

import attr

from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataParamsNamed, convert_enum, convert_iterable


class EntityType(enum.Enum):
    FOR_PROFIT_ORG = 'for-profit organization'
    GOV_ORG = 'governmental organization'
    NONPROFIT_ORG = 'nonprofit organization'
    NOT_FOR_PROFIT_ORG = 'not-for-profit organization'
    PRIV_PERSON = 'private person'


class EntityRole(enum.Enum):
    CLIENT_DEVELOPER = 'client developer'
    CT_LOG_OPERATOR = 'certificate transparency log operator'


@attr.s(frozen=True)
class EntityParams(CryptoDataParamsNamed):
    type = attr.ib(
        converter=convert_enum(EntityType),
        validator=attr.validators.instance_of(EntityType)
    )
    activities = attr.ib(
        converter=convert_iterable(convert_enum(EntityRole)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(EntityRole))
    )


Entity = CryptoDataEnumBase('Entity', CryptoDataEnumBase.get_json_records(EntityParams))


class ClientType(enum.Enum):
    CT_LOG_OPERATOR = 'certificate transparency log operator'
    WEB_BROWSER = 'web browser'


@attr.s(frozen=True)
class ClientParams(CryptoDataParamsNamed):
    type = attr.ib(
        converter=convert_enum(ClientType),
        validator=attr.validators.instance_of(ClientType)
    )
    developer = attr.ib(
        converter=convert_enum(Entity),
        validator=attr.validators.instance_of(Entity)
    )

    def __str__(self):
        return '{} {}'.format(self.developer.value.name, self.name)


Client = CryptoDataEnumBase('Client', CryptoDataEnumBase.get_json_records(ClientParams))

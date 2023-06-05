# -*- coding: utf-8 -*-

import enum

import attr

from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataParamsNamed, convert_enum


class OrganizationParams(CryptoDataParamsNamed):
    pass


Organization = CryptoDataEnumBase('Organization', CryptoDataEnumBase.get_json_records(OrganizationParams))


class ClientType(enum.Enum):
    WEB_BROWSER = 'web browser'


@attr.s
class ClientParams(CryptoDataParamsNamed):
    type = attr.ib(
        converter=convert_enum(ClientType),
        validator=attr.validators.instance_of(ClientType)
    )
    developer = attr.ib(
        converter=convert_enum(Organization),
        validator=attr.validators.instance_of(Organization)
    )

    def __str__(self):
        return '{} {}'.format(self.developer.value.name, self.name)


Client = CryptoDataEnumBase('Client', CryptoDataEnumBase.get_json_records(ClientParams))

# SPDX-License-Identifier: MPL-2.0

import enum

import attr

from cryptodatahub.common.entity import Client
from cryptodatahub.common.types import (
    ClientVersion,
    CryptoDataParamsBase,
    convert_client_version,
    convert_dict_to_object,
    convert_enum,
)


class ClientConfigurationChange(enum.IntEnum):
    pass


@attr.s(frozen=True)
class ClientVersionedParamsBase(CryptoDataParamsBase):
    client = attr.ib(converter=convert_enum(Client), validator=attr.validators.instance_of(Client))
    first_version = attr.ib(converter=convert_client_version(), validator=attr.validators.instance_of(ClientVersion))
    last_version = attr.ib(converter=convert_client_version(), validator=attr.validators.instance_of(ClientVersion))

    def __str__(self):
        return f'{self.client.value} ({self.first_version} - {self.last_version})'


@attr.s(frozen=True)
class ClientVersionedParams(ClientVersionedParamsBase):
    changes = attr.ib(
        converter=frozenset,
        validator=attr.validators.deep_iterable(attr.validators.instance_of(ClientConfigurationChange))
    )


@attr.s(frozen=True)
class ClientParamsBase(CryptoDataParamsBase):
    meta = attr.ib(
        converter=convert_dict_to_object(ClientVersionedParams),
        validator=attr.validators.instance_of(ClientVersionedParams)
    )


def get_client_capabilities_attribute(client_capabilities_class):
    return attr.ib(
        converter=convert_dict_to_object(client_capabilities_class),
        validator=attr.validators.instance_of(client_capabilities_class)
    )

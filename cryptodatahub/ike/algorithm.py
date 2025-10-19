# -*- coding: utf-8 -*-

import enum

import attr

from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumCodedBase,
    CryptoDataParamsEnumNumeric,
    convert_enum,
)


@attr.s(frozen=True)
class Ikev2ExchangeTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv2 exchange type parameters."""

    description = attr.ib(
        validator=attr.validators.instance_of(str)
    )

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2ExchangeType = CryptoDataEnumCodedBase(
    'ExchangeType',
    CryptoDataEnumBase.get_json_records(Ikev2ExchangeTypeParams)
)


class Ikev2NotifyLevel(enum.Enum):
    """Notify level."""
    ERROR = enum.auto()
    STATUS = enum.auto()


@attr.s(frozen=True)
class Ikev2NotifyTypeParams(CryptoDataParamsEnumNumeric):
    """Notify type parameters."""

    level = attr.ib(
        converter=convert_enum(Ikev2NotifyLevel),
        validator=attr.validators.instance_of(Ikev2NotifyLevel)
    )

    @classmethod
    def get_code_size(cls):
        return 2


Ikev2NotifyType = CryptoDataEnumCodedBase('NotifyType', CryptoDataEnumBase.get_json_records(Ikev2NotifyTypeParams))


class Ikev2TransformAttributeFormat(enum.Enum):
    """IKEv2 attribute format."""
    TV = enum.auto()
    TLV = enum.auto()


@attr.s(frozen=True)
class Ikev2TransformAttributeTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv2 attribute type parameters."""

    format = attr.ib(
        converter=convert_enum(Ikev2TransformAttributeFormat),
        validator=attr.validators.instance_of(Ikev2TransformAttributeFormat)
    )

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2TransformAttributeType = CryptoDataEnumCodedBase(
    'AttributeType',
    CryptoDataEnumBase.get_json_records(Ikev2TransformAttributeTypeParams)
)


@attr.s(frozen=True)
class Ikev2ExtendedSequenceNumberParams(CryptoDataParamsEnumNumeric):
    """Extended sequence number parameters."""

    description = attr.ib(
        validator=attr.validators.instance_of(str)
    )

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2ExtendedSequenceNumber = CryptoDataEnumBase(
    'ExtendedSequenceNumber',
    CryptoDataEnumBase.get_json_records(Ikev2ExtendedSequenceNumberParams)
)


@attr.s(frozen=True)
class Ikev2IpCompTransformIdParams(CryptoDataParamsEnumNumeric):
    """IP compression transform ID parameters."""

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2IpCompTransformId = CryptoDataEnumBase(
    'IpCompTransformId',
    CryptoDataEnumBase.get_json_records(Ikev2IpCompTransformIdParams)
)


@attr.s(frozen=True)
class Ikev2TransformTypeParams(CryptoDataParamsEnumNumeric):
    """Transform type parameters."""

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2TransformType = CryptoDataEnumCodedBase(
    'TransformType',
    CryptoDataEnumBase.get_json_records(Ikev2TransformTypeParams)
)


@attr.s(frozen=True)
class Ikev2ProtocolIdParams(CryptoDataParamsEnumNumeric):
    """Protocol ID parameters."""

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2ProtocolId = CryptoDataEnumCodedBase(
    'ProtocolId',
    CryptoDataEnumBase.get_json_records(Ikev2ProtocolIdParams)
)


@attr.s
class IkePayloadTypeParams(CryptoDataParamsEnumNumeric):
    """ISAKMP payload type parameters."""

    description = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_code_size(cls):
        return 1


IkePayloadType = CryptoDataEnumCodedBase(
    'PayloadType',
    CryptoDataEnumBase.get_json_records(IkePayloadTypeParams)
)

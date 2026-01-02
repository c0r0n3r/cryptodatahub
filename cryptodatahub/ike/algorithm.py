# -*- coding: utf-8 -*-

import enum
import typing

import attr

from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumCodedBase,
    CryptoDataParamsEnumNumeric,
    convert_enum,
    convert_iterable,
    convert_variadic,
)
from cryptodatahub.common.algorithm import BlockCipher, Hash, MAC, NamedGroup, BlockCipherMode
from cryptodatahub.common.parameter import DHParamWellKnown


@attr.s(frozen=True)
class Ikev2PseudorandomFunctionParams(CryptoDataParamsEnumNumeric):
    """Pseudorandom function parameters."""

    mac: MAC = attr.ib(
        converter=convert_enum(MAC),
        validator=attr.validators.instance_of(MAC)
    )

    def __str__(self):
        return self.mac.value.name

    @classmethod
    def get_code_size(cls):
        return 2


Ikev2PseudorandomFunction = CryptoDataEnumCodedBase(
    'PseudorandomFunction',
    CryptoDataEnumBase.get_json_records(Ikev2PseudorandomFunctionParams)
)


@attr.s(frozen=True)
class Ikev2AuthenticationMethodParams(CryptoDataParamsEnumNumeric):
    """Authentication method parameters."""

    description: str = attr.ib(
        validator=attr.validators.instance_of(str)
    )

    def __str__(self):
        return self.description

    @classmethod
    def get_code_size(cls):
        return 2


Ikev2AuthenticationMethod = CryptoDataEnumCodedBase(
    'AuthenticationMethod',
    CryptoDataEnumBase.get_json_records(Ikev2AuthenticationMethodParams)
)


@attr.s(frozen=True)
class Ikev2IntegrityAlgorithmParams(CryptoDataParamsEnumNumeric):
    """Integrity algorithm parameters."""

    hmac: typing.Optional[MAC] = attr.ib(
        converter=convert_enum(MAC),
        validator=attr.validators.optional(attr.validators.instance_of(MAC))
    )

    def __str__(self):
        if self.hmac is None:
            return "null"

        return self.hmac.value.name

    @classmethod
    def get_code_size(cls):
        return 2


Ikev2IntegrityAlgorithm = CryptoDataEnumCodedBase(
    'IntegrityAlgorithm',
    CryptoDataEnumBase.get_json_records(Ikev2IntegrityAlgorithmParams)
)


@attr.s(frozen=True)
class Ikev2DiffieHellmanGroupParams(CryptoDataParamsEnumNumeric):
    """Diffie-Hellman group parameters."""

    key_parameter: typing.Union[NamedGroup, DHParamWellKnown, str] = attr.ib(
        converter=convert_variadic((convert_enum(NamedGroup), convert_enum(DHParamWellKnown))),
        validator=attr.validators.optional(
            attr.validators.instance_of((NamedGroup, DHParamWellKnown, str))
        )
    )

    def __str__(self):
        return self.key_parameter.value.name

    @classmethod
    def get_code_size(cls):
        return 2


Ikev2DiffieHellmanGroup = CryptoDataEnumCodedBase(
    'DiffieHellmanGroup',
    CryptoDataEnumBase.get_json_records(Ikev2DiffieHellmanGroupParams)
)


@attr.s(frozen=True)
class Ikev2EncryptionAlgorithmParams(CryptoDataParamsEnumNumeric):
    """Encryption algorithm parameters."""

    bulk_ciphers: typing.List[BlockCipher] = attr.ib(
        converter=convert_iterable(convert_enum(BlockCipher)),
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(BlockCipher)),
    )
    block_cipher_mode: typing.Optional[BlockCipherMode] = attr.ib(
        converter=convert_enum(BlockCipherMode),
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode)),
    )

    def __str__(self):
        if not self.bulk_ciphers:
            return 'null'

        cipher_name = self.bulk_ciphers[0].value.name
        if self.block_cipher_mode is None:
            return cipher_name

        return f'{cipher_name} ({self.block_cipher_mode.value.name})'

    @classmethod
    def get_code_size(cls):
        return 2


Ikev2EncryptionAlgorithm = CryptoDataEnumCodedBase(
    'EncryptionAlgorithm',
    CryptoDataEnumBase.get_json_records(Ikev2EncryptionAlgorithmParams)
)


@attr.s(frozen=True)
class Ikev2HashAlgorithmParams(CryptoDataParamsEnumNumeric):
    """Hash algorithm parameters."""

    hash_algorithm: Hash = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.instance_of(Hash)
    )

    def __str__(self):
        return self.hash_algorithm.value.name

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2HashAlgorithm = CryptoDataEnumBase(
    'HashAlgorithm',
    CryptoDataEnumBase.get_json_records(Ikev2HashAlgorithmParams)
)


@attr.s(frozen=True)
class Ikev2ExchangeTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv2 exchange type parameters."""

    description: str = attr.ib(
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

    level: Ikev2NotifyLevel = attr.ib(
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

    description: str = attr.ib(
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

    description: str = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_code_size(cls):
        return 1


IkePayloadType = CryptoDataEnumCodedBase(
    'PayloadType',
    CryptoDataEnumBase.get_json_records(IkePayloadTypeParams)
)

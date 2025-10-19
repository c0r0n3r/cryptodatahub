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


@attr.s(frozen=True)
class Ikev1ExchangeTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 exchange type parameters."""

    description: str = attr.ib(
        validator=attr.validators.instance_of(str)
    )

    @classmethod
    def get_code_size(cls):
        return 1


Ikev1ExchangeType = CryptoDataEnumCodedBase(
    'ExchangeType',
    CryptoDataEnumBase.get_json_records(Ikev1ExchangeTypeParams)
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
class Ikev2PayloadTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv2 payload type parameters."""

    description: str = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_code_size(cls):
        return 1


Ikev2PayloadType = CryptoDataEnumCodedBase(
    'PayloadType',
    CryptoDataEnumBase.get_json_records(Ikev2PayloadTypeParams)
)


@attr.s(frozen=True)
class Ikev1DoiParams(CryptoDataParamsEnumNumeric):
    """IKEv1 DOI type parameters."""

    @classmethod
    def get_code_size(cls):
        return 4


Ikev1Doi = CryptoDataEnumCodedBase(
    'Doi',
    CryptoDataEnumBase.get_json_records(Ikev1DoiParams)
)


class Ikev1NotifyLevel(enum.Enum):
    """IKEv1 notify level."""
    ERROR = enum.auto()
    STATUS = enum.auto()


@attr.s(frozen=True)
class Ikev1NotifyTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 notify type parameters."""

    level: Ikev1NotifyLevel = attr.ib(
        converter=convert_enum(Ikev1NotifyLevel),
        validator=attr.validators.instance_of(Ikev1NotifyLevel)
    )

    @classmethod
    def get_code_size(cls):
        return 2


Ikev1NotifyType = CryptoDataEnumCodedBase(
    'NotifyType',
    CryptoDataEnumBase.get_json_records(Ikev1NotifyTypeParams)
)


class Ikev1AttributeFormat(enum.Enum):
    """IKEv1 attribute format."""
    BASIC = enum.auto()  # B
    VARIABLE = enum.auto()  # V


@attr.s(frozen=True)
class Ikev1AttributeTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 attribute type parameters."""

    format: Ikev1AttributeFormat = attr.ib(
        converter=convert_enum(Ikev1AttributeFormat),
        validator=attr.validators.instance_of(Ikev1AttributeFormat)
    )

    @classmethod
    def get_code_size(cls):
        return 1


Ikev1AttributeType = CryptoDataEnumCodedBase(
    'AttributeType',
    CryptoDataEnumBase.get_json_records(Ikev1AttributeTypeParams)
)


@attr.s(frozen=True)
class Ikev1TransformIdParams(CryptoDataParamsEnumNumeric):
    """IKEv1 transform ID parameters."""

    description: str = attr.ib(
        validator=attr.validators.instance_of(str)
    )

    @classmethod
    def get_code_size(cls):
        return 1


Ikev1TransformId = CryptoDataEnumCodedBase(
    'TransformId',
    CryptoDataEnumBase.get_json_records(Ikev1TransformIdParams)
)


@attr.s(frozen=True)
class Ikev1ProtocolIdParams(CryptoDataParamsEnumNumeric):
    """IKEv1 protocol ID parameters."""

    @classmethod
    def get_code_size(cls):
        return 1


Ikev1ProtocolId = CryptoDataEnumCodedBase(
    'ProtocolId',
    CryptoDataEnumBase.get_json_records(Ikev1ProtocolIdParams)
)


@attr.s(frozen=True)
class Ikev1TransformTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 transform type parameters."""

    @classmethod
    def get_code_size(cls):
        return 1


Ikev1TransformType = CryptoDataEnumCodedBase(
    'TransformType',
    CryptoDataEnumBase.get_json_records(Ikev1TransformTypeParams)
)


@attr.s(frozen=True)
class Ikev1PayloadTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 payload type parameters."""

    description: str = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_code_size(cls):
        return 1


Ikev1PayloadType = CryptoDataEnumCodedBase(
    'PayloadType',
    CryptoDataEnumBase.get_json_records(Ikev1PayloadTypeParams)
)


@attr.s(frozen=True)
class Ikev1EncryptionAlgorithmParams(CryptoDataParamsEnumNumeric):
    """IKEv1 encryption algorithm parameters."""

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


Ikev1EncryptionAlgorithm = CryptoDataEnumCodedBase(
    'EncryptionAlgorithm',
    CryptoDataEnumBase.get_json_records(Ikev1EncryptionAlgorithmParams)
)


@attr.s(frozen=True)
class Ikev1HashAlgorithmParams(CryptoDataParamsEnumNumeric):
    """IKEv1 hash algorithm parameters."""

    hash: Hash = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.instance_of(Hash)
    )

    def __str__(self):
        return self.hash.value.name

    @classmethod
    def get_code_size(cls):
        return 2


Ikev1HashAlgorithm = CryptoDataEnumCodedBase(
    'Ikev1HashAlgorithm',
    CryptoDataEnumBase.get_json_records(Ikev1HashAlgorithmParams)
)


@attr.s(frozen=True)
class Ikev1AuthenticationMethodParams(CryptoDataParamsEnumNumeric):
    """IKEv1 authentication method parameters."""

    @classmethod
    def get_code_size(cls):
        return 2


Ikev1AuthenticationMethod = CryptoDataEnumCodedBase(
    'Ikev1AuthenticationMethod',
    CryptoDataEnumBase.get_json_records(Ikev1AuthenticationMethodParams)
)


@attr.s(frozen=True)
class Ikev1GroupTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 group type parameters."""

    description: str = attr.ib(
        validator=attr.validators.instance_of(str)
    )

    @classmethod
    def get_code_size(cls):
        return 2


Ikev1GroupType = CryptoDataEnumCodedBase(
    'GroupType',
    CryptoDataEnumBase.get_json_records(Ikev1GroupTypeParams)
)


@attr.s(frozen=True)
class Ikev1LifeTypeParams(CryptoDataParamsEnumNumeric):
    """IKEv1 life type parameters."""

    @classmethod
    def get_code_size(cls):
        return 2


Ikev1LifeType = CryptoDataEnumCodedBase(
    'LifeType',
    CryptoDataEnumBase.get_json_records(Ikev1LifeTypeParams)
)


@attr.s(frozen=True)
class Ikev1DiffieHellmanGroupParams(CryptoDataParamsEnumNumeric):
    """IKEv1 Diffie-Hellman group parameters."""

    key_parameter: typing.Union[NamedGroup, DHParamWellKnown, str] = attr.ib(
        converter=convert_variadic((convert_enum(NamedGroup), convert_enum(DHParamWellKnown))),
        validator=attr.validators.instance_of((NamedGroup, DHParamWellKnown, str))
    )

    def __str__(self):
        return self.key_parameter.value.name

    @classmethod
    def get_code_size(cls):
        return 2


Ikev1DiffieHellmanGroup = CryptoDataEnumCodedBase(
    'DiffieHellmanGroup',
    CryptoDataEnumBase.get_json_records(Ikev1DiffieHellmanGroupParams)
)

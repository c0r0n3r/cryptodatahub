# -*- coding: utf-8 -*-

import enum
import six

import attr

from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumOIDBase,
    CryptoDataParamsNamed,
    CryptoDataParamsOIDOptional,
    convert_enum,
)


@attr.s(frozen=True)
class AuthenticationParams(CryptoDataParamsOIDOptional):
    anonymous = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s(frozen=True)
class BlockCipherParams(CryptoDataParamsNamed):
    key_size = attr.ib(validator=attr.validators.instance_of(int))
    block_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s(frozen=True)
class BlockCipherModeParams(CryptoDataParamsNamed):
    pass


@attr.s(frozen=True)
class HashParams(CryptoDataParamsOIDOptional):
    digest_size = attr.ib(attr.validators.instance_of(int))


@attr.s(frozen=True)
class KeyExchangeParams(CryptoDataParamsNamed):
    forward_secret = attr.ib(validator=attr.validators.instance_of(bool))


class NamedGroupType(enum.IntEnum):
    ELLIPTIC_CURVE = 1
    DH_PARAM = 2


@attr.s(frozen=True)
class NamedGroupParams(CryptoDataParamsOIDOptional):
    size = attr.ib(validator=attr.validators.instance_of(int))
    group_type = attr.ib(
        converter=convert_enum(NamedGroupType),
        validator=attr.validators.instance_of(NamedGroupType),
    )


Authentication = CryptoDataEnumOIDBase('Authentication', CryptoDataEnumOIDBase.get_json_records(AuthenticationParams))
BlockCipher = CryptoDataEnumBase('BlockCipher', CryptoDataEnumBase.get_json_records(BlockCipherParams))
BlockCipherMode = CryptoDataEnumBase('BlockCipherMode', CryptoDataEnumBase.get_json_records(BlockCipherModeParams))
Hash = CryptoDataEnumOIDBase('Hash', CryptoDataEnumOIDBase.get_json_records(HashParams))
KeyExchange = CryptoDataEnumBase('KeyExchange', CryptoDataEnumBase.get_json_records(KeyExchangeParams))
NamedGroup = CryptoDataEnumOIDBase('NamedGroup', CryptoDataEnumOIDBase.get_json_records(NamedGroupParams))


@attr.s(frozen=True)
class MACParams(CryptoDataParamsOIDOptional):
    digest_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))
    hash_algorithm = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((Hash, six.string_types))))

    def __attrs_post_init__(self):
        if (self.digest_size is None) == (self.hash_algorithm is None):
            raise ValueError()

        if isinstance(self.hash_algorithm, six.string_types):
            object.__setattr__(self, 'hash_algorithm', Hash[self.hash_algorithm])

        if self.digest_size is None:
            object.__setattr__(self, 'digest_size', self.hash_algorithm.value.digest_size)

        attr.validate(self)


MAC = CryptoDataEnumOIDBase('MAC', CryptoDataEnumOIDBase.get_json_records(MACParams))


@attr.s(frozen=True)
class SignatureParams(CryptoDataParamsOIDOptional):
    key_type = attr.ib(
        converter=convert_enum(Authentication),
        validator=attr.validators.instance_of(Authentication),
    )
    hash_algorithm = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.instance_of(Hash),
    )


Signature = CryptoDataEnumOIDBase('Signature', CryptoDataEnumOIDBase.get_json_records(SignatureParams))

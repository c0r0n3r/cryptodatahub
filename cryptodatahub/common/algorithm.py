# -*- coding: utf-8 -*-

import enum

import attr

from cryptodatahub.common.grade import (
    AttackType,
    Grade,
    GradeableComplex,
    GradeableVulnerabilities,
    Vulnerability,
)
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumOIDBase,
    CryptoDataParamsEnumString,
    CryptoDataParamsNamed,
    CryptoDataParamsOIDOptional,
    convert_enum,
)


@attr.s(frozen=True)
class AuthenticationParams(CryptoDataParamsOIDOptional, GradeableVulnerabilities):
    anonymous = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    def get_gradeable_name(cls):
        return 'authentication'


@attr.s(frozen=True)
class BlockCipherParams(CryptoDataParamsNamed, GradeableVulnerabilities):
    key_size = attr.ib(validator=attr.validators.instance_of(int))
    block_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))

    @classmethod
    def get_gradeable_name(cls):
        return 'block cipher'


@attr.s(frozen=True)
class BlockCipherModeParams(CryptoDataParamsNamed, GradeableVulnerabilities):
    @classmethod
    def get_gradeable_name(cls):
        return 'block cipher mode'


@attr.s(frozen=True)
class HashParams(CryptoDataParamsOIDOptional, GradeableVulnerabilities):
    digest_size = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    def get_gradeable_name(cls):
        return 'hash'


@attr.s(frozen=True)
class KeyExchangeParams(CryptoDataParamsNamed, GradeableVulnerabilities):
    forward_secret = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    def get_gradeable_name(cls):
        return 'key exchange'


NamedGroupType = enum.Enum('NamedGroupType', 'ELLIPTIC_CURVE FINITE_FIELD HYBRID_PQS')


@attr.s(frozen=True)
class NamedGroupParams(CryptoDataParamsOIDOptional, GradeableVulnerabilities):
    size = attr.ib(validator=attr.validators.instance_of(int))
    group_type = attr.ib(
        converter=convert_enum(NamedGroupType),
        validator=attr.validators.instance_of(NamedGroupType),
    )

    @classmethod
    def get_gradeable_name(cls):
        return 'named group'


Authentication = CryptoDataEnumOIDBase('Authentication', CryptoDataEnumOIDBase.get_json_records(AuthenticationParams))
BlockCipher = CryptoDataEnumBase('BlockCipher', CryptoDataEnumBase.get_json_records(BlockCipherParams))
BlockCipherMode = CryptoDataEnumBase('BlockCipherMode', CryptoDataEnumBase.get_json_records(BlockCipherModeParams))
Hash = CryptoDataEnumOIDBase('Hash', CryptoDataEnumOIDBase.get_json_records(HashParams))
KeyExchange = CryptoDataEnumBase('KeyExchange', CryptoDataEnumBase.get_json_records(KeyExchangeParams))
NamedGroup = CryptoDataEnumOIDBase('NamedGroup', CryptoDataEnumOIDBase.get_json_records(NamedGroupParams))


@attr.s(frozen=True)
class MACParams(CryptoDataParamsOIDOptional, GradeableVulnerabilities):
    digest_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))
    hash_algorithm = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((Hash, str))))

    @classmethod
    def get_gradeable_name(cls):
        return 'MAC'

    def __attrs_post_init__(self):
        if (self.digest_size is None) == (self.hash_algorithm is None):
            raise ValueError()

        if isinstance(self.hash_algorithm, str):
            object.__setattr__(self, 'hash_algorithm', Hash[self.hash_algorithm])

        if self.digest_size is None:
            object.__setattr__(self, 'digest_size', self.hash_algorithm.value.digest_size)

        attr.validate(self)


MAC = CryptoDataEnumOIDBase('MAC', CryptoDataEnumOIDBase.get_json_records(MACParams))


@attr.s(frozen=True)
class MACModeParams(CryptoDataParamsEnumString, GradeableVulnerabilities):
    name = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_gradeable_name(cls):
        return 'MAC mode'


class MACMode(enum.Enum):
    ENCRYPT_THEN_MAC = MACModeParams(
        code='encrypt_then_mac',
        name='encrypt then MAC',
        vulnerabilities=[],
    )
    ENCRYPT_AND_MAC = MACModeParams(
        code='encrypt_and_mac',
        name='encrypt and MAC',
        vulnerabilities=[
            Vulnerability(attack_type=AttackType.FORGERY_ATTACK, grade=Grade.WEAK, named=None),
        ],
    )
    MAC_THEN_ENCRYP = MACModeParams(
        code='mac_then_encrypt',
        name='MAC then encrypt',
        vulnerabilities=[],
    )


@attr.s(frozen=True)
class SignatureParams(CryptoDataParamsOIDOptional, GradeableComplex):
    key_type = attr.ib(
        converter=convert_enum(Authentication),
        validator=attr.validators.instance_of(Authentication),
    )
    hash_algorithm = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.optional(attr.validators.instance_of(Hash)),
    )

    def __attrs_post_init__(self):
        object.__setattr__(self, 'gradeables', [self.hash_algorithm.value])

        attr.validate(self)


Signature = CryptoDataEnumOIDBase('Signature', CryptoDataEnumOIDBase.get_json_records(SignatureParams))

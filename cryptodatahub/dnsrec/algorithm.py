# -*- coding: utf-8 -*-

import attr
import six

from cryptodatahub.common.algorithm import Hash, KeyExchange, Signature
from cryptodatahub.common.grade import GradeableComplex
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumCodedBase,
    CryptoDataParamsEnumNumeric,
    convert_enum,
    convert_variadic,
)


@attr.s(frozen=True)
class AlgorithmParams(CryptoDataParamsEnumNumeric, GradeableComplex):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    zone_transfer = attr.ib(validator=attr.validators.instance_of(bool))
    transaction_security = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)))
    algorithm = attr.ib(
        converter=convert_variadic((convert_enum(Signature), convert_enum(KeyExchange))),
        validator=attr.validators.optional(attr.validators.instance_of(CryptoDataEnumBase))
    )

    def __attrs_post_init__(self):
        if self.algorithm is None:
            object.__setattr__(self, 'gradeables', [])
        else:
            object.__setattr__(self, 'gradeables', [self.algorithm.value])

        attr.validate(self)

    @classmethod
    def get_code_size(cls):
        return 1

    def __str__(self):
        return self.name


DnsSecAlgorithm = CryptoDataEnumCodedBase('DnsSecAlgorithm', CryptoDataEnumCodedBase.get_json_records(AlgorithmParams))


@attr.s(frozen=True)
class DigestTypeParams(CryptoDataParamsEnumNumeric, GradeableComplex):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    hash = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.instance_of(Hash),
    )

    def __attrs_post_init__(self):
        object.__setattr__(self, 'gradeables', [self.hash.value])

        attr.validate(self)

    @classmethod
    def get_code_size(cls):
        return 1

    def __str__(self):
        return self.name


DnsSecDigestType = CryptoDataEnumCodedBase(
    'DnsSecDigestType', CryptoDataEnumCodedBase.get_json_records(DigestTypeParams)
)


@attr.s(frozen=True)
class RrTypeParams(CryptoDataParamsEnumNumeric):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    description = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    def get_code_size(cls):
        return 2

    def __str__(self):
        return self.name


DnsRrType = CryptoDataEnumCodedBase(
    'DnsRrType', CryptoDataEnumCodedBase.get_json_records(RrTypeParams)
)

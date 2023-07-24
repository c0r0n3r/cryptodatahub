# -*- coding: utf-8 -*-

import attr

import six

from cryptodatahub.common.algorithm import KeyExchange, Signature
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumCodedBase,
    CryptoDataParamsEnumNumeric,
    convert_enum,
    convert_variadic,
)


@attr.s(frozen=True)
class AlgorithmParams(CryptoDataParamsEnumNumeric):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    zone_transfer = attr.ib(validator=attr.validators.instance_of(bool))
    transaction_security = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)))
    algorithm = attr.ib(
        converter=convert_variadic((convert_enum(Signature), convert_enum(KeyExchange))),
        validator=attr.validators.optional(attr.validators.instance_of(CryptoDataEnumBase))
    )

    @classmethod
    def get_code_size(cls):
        return 1

    def __str__(self):
        return self.name


DnsSecAlgorithm = CryptoDataEnumCodedBase('DnsSecAlgorithm', CryptoDataEnumCodedBase.get_json_records(AlgorithmParams))

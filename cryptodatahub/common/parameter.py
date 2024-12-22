# -*- coding: utf-8 -*-

import attr

from cryptodatahub.common.entity import Entity, Server
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import GradeableVulnerabilities
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataParamsBase,
    CryptoDataParamsNamed,
    convert_big_enum,
    convert_dict_to_object,
    convert_enum,
    convert_iterable,
    convert_variadic,
)


@attr.s(frozen=True)
class StandardParams(CryptoDataParamsNamed):
    publisher = attr.ib(
        converter=convert_enum(Entity),
        validator=attr.validators.instance_of(Entity),
    )


Standard = CryptoDataEnumBase('Standard', CryptoDataEnumBase.get_json_records(StandardParams))


@attr.s(eq=False, frozen=True)
class DHParameterNumbers():
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'p'},
    )
    g = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'g'},
    )
    q = attr.ib(  # pylint: disable=invalid-name
        default=None,
        converter=convert_big_enum(),
        validator=attr.validators.optional(attr.validators.instance_of(int)),
        metadata={'human_readable_name': 'q'},
    )

    def __eq__(self, other):
        return self.p == other.p and self.g == other.g and (self.q is None or self.q == other.q)


@attr.s(eq=False, frozen=True)
class DHParamWellKnownParams(CryptoDataParamsBase, GradeableVulnerabilities):
    parameter_numbers = attr.ib(
        converter=convert_dict_to_object(DHParameterNumbers),
        validator=attr.validators.instance_of(DHParameterNumbers)
    )
    name = attr.ib(validator=attr.validators.instance_of(str))
    source = attr.ib(
        converter=convert_variadic((convert_enum(Entity), convert_enum(Server))),
        validator=attr.validators.instance_of((Entity, Server))
    )
    standards = attr.ib(
        converter=convert_iterable(convert_enum(Standard)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(Standard))
    )
    key_size = attr.ib(validator=attr.validators.instance_of(int))
    safe_prime = attr.ib(default=True, validator=attr.validators.instance_of(bool))

    @classmethod
    def get_gradeable_name(cls):
        return 'DH parameter'

    def __str__(self):
        if self.standards:
            standards_str = ', '.join(map(lambda standard: standard.value.name, self.standards))
            return f'{self.name} ({standards_str})'

        return f'{self.key_size}-bit {self.source.value.name} {self.name} DH parameter'


class DHParamWellKnownBase(CryptoDataEnumBase):
    @classmethod
    def from_parameter_numbers(cls, parameter_numbers):
        return cls._from_attr('parameter_numbers', parameter_numbers)


DHParamWellKnown = DHParamWellKnownBase(
    'DHParamWellKnown', DHParamWellKnownBase.get_json_records(DHParamWellKnownParams)
)


@attr.s
class ECParameterNumbers():
    a = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'a'},
    )
    b = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'b'},
    )
    x = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'x'},
    )
    y = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'y'},
    )


@attr.s(eq=False, frozen=True)
class ECParamWellKnownParams(CryptoDataParamsNamed):
    standards = attr.ib(
        converter=convert_iterable(convert_enum(Standard)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(Standard))
    )
    aliases = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(str)))
    parameter_numbers = attr.ib(
        converter=convert_dict_to_object(ECParameterNumbers),
        validator=attr.validators.instance_of(ECParameterNumbers)
    )


class ECParamWellKnownBase(CryptoDataEnumBase):
    @classmethod
    def from_parameter_numbers(cls, parameter_numbers):
        return cls._from_attr('parameter_numbers', parameter_numbers)

    @classmethod
    def from_named_group(cls, named_group):
        try:
            ec_param = cls[named_group.name]
        except KeyError as e:
            raise InvalidValue(named_group, cls) from e

        return ec_param


ECParamWellKnown = ECParamWellKnownBase(
    'ECParamWellKnown', ECParamWellKnownBase.get_json_records(ECParamWellKnownParams)
)

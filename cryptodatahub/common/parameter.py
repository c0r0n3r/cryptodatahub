# -*- coding: utf-8 -*-

import six
import attr

from cryptodatahub.common.entity import Entity, Server
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
    pass


Standard = CryptoDataEnumBase('Standard', CryptoDataEnumBase.get_json_records(StandardParams))


@attr.s(eq=False, frozen=True)
class DHParameterNumbers(object):
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'p'},
    )
    g = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'g'},
    )
    q = attr.ib(  # pylint: disable=invalid-name
        default=None,
        converter=convert_big_enum(),
        validator=attr.validators.optional(attr.validators.instance_of(six.integer_types)),
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
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    source = attr.ib(
        converter=convert_variadic((convert_enum(Entity), convert_enum(Server))),
        validator=attr.validators.instance_of((Entity, Server))
    )
    standards = attr.ib(
        converter=convert_iterable(convert_enum(Standard)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(Standard))
    )
    key_size = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    safe_prime = attr.ib(default=True, validator=attr.validators.instance_of(bool))

    @classmethod
    def get_gradeable_name(cls):
        return 'DH parameter'

    def __str__(self):
        if self.standards:
            return '{} ({})'.format(self.name, ', '.join(map(lambda standard: standard.value.name, self.standards)))

        return '{}-bit {} {} DH parameter'.format(self.key_size, self.source.value.name, self.name)


DHParamWellKnown = CryptoDataEnumBase('DHParamWellKnown', CryptoDataEnumBase.get_json_records(DHParamWellKnownParams))

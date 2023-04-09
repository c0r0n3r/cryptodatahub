# -*- coding: utf-8 -*-

import six
import attr

from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataParamsBase,
    convert_big_enum,
    convert_dict_to_object,
)


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


@attr.s(eq=False)
class DHParamWellKnownParams(CryptoDataParamsBase):
    parameter_numbers = attr.ib(
        converter=convert_dict_to_object(DHParameterNumbers),
        validator=attr.validators.instance_of(DHParameterNumbers)
    )
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    source = attr.ib(validator=attr.validators.instance_of(six.string_types))
    key_size = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    safe_prime = attr.ib(default=True, validator=attr.validators.instance_of(bool))

    def __eq__(self, other):
        return self.parameter_numbers == other.parameter_numbers

    def __str__(self):
        return '{} ({})'.format(self.name, self.source)


DHParamWellKnown = CryptoDataEnumBase('DHParamWellKnown', CryptoDataEnumBase.get_json_records(DHParamWellKnownParams))

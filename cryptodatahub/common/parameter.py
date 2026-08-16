# SPDX-License-Identifier: MPL-2.0

import abc
import enum

import attr

from cryptodatahub.common.algorithm import NistSecurityLevel
from cryptodatahub.common.entity import Entity, Server
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import GradeableVulnerabilities
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumOIDBase,
    CryptoDataParamsNamed,
    CryptoDataParamsOIDOptional,
    HexData,
    convert_big_enum,
    convert_dict_to_object,
    convert_enum,
    convert_hex_data,
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


@attr.s(frozen=True)
class PaperParams(CryptoDataParamsNamed):
    authors = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(str)))
    url = attr.ib(
        validator=attr.validators.instance_of(str),
        metadata={'human_readable_name': 'URL', 'human_friendly': False},
    )


class PaperBase(CryptoDataEnumBase):
    @classmethod
    def get_json_encoding(cls):
        return 'utf-8'


Paper = PaperBase('Paper', PaperBase.get_json_records(PaperParams))


@attr.s(eq=False, frozen=True)
class DHParameterNumbers:
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
class ParamWellKnownBase(CryptoDataParamsNamed, GradeableVulnerabilities):
    aliases = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(str)))
    sources = attr.ib(
        converter=convert_iterable(convert_variadic((
            convert_enum(Standard),
            convert_enum(Paper),
            convert_enum(Entity),
            convert_enum(Server),
        ))),
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of((Standard, Paper, Entity, Server))
        ),
    )

    @classmethod
    @abc.abstractmethod
    def get_gradeable_name(cls):
        raise NotImplementedError()


@attr.s(eq=False, frozen=True)
class DHParamWellKnownParams(ParamWellKnownBase):
    parameter_numbers = attr.ib(
        converter=convert_dict_to_object(DHParameterNumbers),
        validator=attr.validators.instance_of(DHParameterNumbers)
    )
    key_size = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    def get_gradeable_name(cls):
        return 'DH parameter'

    def __str__(self):
        standards = [source for source in self.sources if isinstance(source, Standard)]
        if standards:
            standards_str = ', '.join(map(lambda standard: standard.value.name, standards))
            return f'{self.name} ({standards_str})'

        origin = next(source for source in self.sources if not isinstance(source, Standard))

        return f'{self.key_size}-bit {origin.value.name} {self.name} DH parameter'


class DHParamWellKnownBase(CryptoDataEnumBase):
    @classmethod
    def from_parameter_numbers(cls, parameter_numbers):
        return cls._from_attr('parameter_numbers', parameter_numbers)


DHParamWellKnown = DHParamWellKnownBase(
    'DHParamWellKnown', DHParamWellKnownBase.get_json_records(DHParamWellKnownParams)
)


ECParameterForm = enum.Enum(
    'ECParameterForm',
    'WEIERSTRASS_PRIME WEIERSTRASS_BINARY WEIERSTRASS_BINARY_NORMAL_BASIS MONTGOMERY TWISTED_EDWARDS '
    'WEIERSTRASS_EXTENSION TWISTED_EDWARDS_EXTENSION'
)


@attr.s
class ECParameterNumbersWeierstrassPrime:  # pylint: disable=too-many-instance-attributes
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'p'},
    )
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
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )
    seed = attr.ib(
        converter=convert_hex_data(),
        validator=attr.validators.optional(attr.validators.instance_of(HexData)),
        metadata={'human_readable_name': 'seed'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.WEIERSTRASS_PRIME


@attr.s
class ECParameterNumbersWeierstrassBinary:  # pylint: disable=too-many-instance-attributes
    m = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'm'},
    )
    k1 = attr.ib(
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'k1'},
    )
    k2 = attr.ib(
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'k2'},
    )
    k3 = attr.ib(
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'k3'},
    )
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
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )
    seed = attr.ib(
        converter=convert_hex_data(),
        validator=attr.validators.optional(attr.validators.instance_of(HexData)),
        metadata={'human_readable_name': 'seed'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.WEIERSTRASS_BINARY


@attr.s
class ECParameterNumbersWeierstrassBinaryNormalBasis:  # pylint: disable=too-many-instance-attributes
    m = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'm'},
    )
    gaussian_normal_basis_type = attr.ib(
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'Gaussian normal basis type'},
    )
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
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )
    seed = attr.ib(
        converter=convert_hex_data(),
        validator=attr.validators.optional(attr.validators.instance_of(HexData)),
        metadata={'human_readable_name': 'seed'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.WEIERSTRASS_BINARY_NORMAL_BASIS


@attr.s
class ECParameterNumbersMontgomery:
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'p'},
    )
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
    u = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'u'},
    )
    v = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'v'},
    )
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.MONTGOMERY


@attr.s
class ECParameterNumbersTwistedEdwards:
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'p'},
    )
    a = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'a'},
    )
    d = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'd'},
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
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.TWISTED_EDWARDS


def convert_extension_field_element():
    return convert_iterable(convert_big_enum())


def validate_extension_field_element():
    return attr.validators.deep_iterable(attr.validators.instance_of(int))


@attr.s
class ECParameterNumbersWeierstrassExtension:  # pylint: disable=too-many-instance-attributes
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'p'},
    )
    reduction_polynomial_constants = attr.ib(
        converter=convert_iterable(convert_extension_field_element()),
        validator=attr.validators.deep_iterable(validate_extension_field_element()),
        metadata={'human_readable_name': 'reduction polynomial constants'},
    )
    a = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'a'},
    )
    b = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'b'},
    )
    x = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'x'},
    )
    y = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'y'},
    )
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.WEIERSTRASS_EXTENSION


@attr.s
class ECParameterNumbersTwistedEdwardsExtension:  # pylint: disable=too-many-instance-attributes
    p = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'p'},
    )
    reduction_polynomial_constants = attr.ib(
        converter=convert_iterable(convert_extension_field_element()),
        validator=attr.validators.deep_iterable(validate_extension_field_element()),
        metadata={'human_readable_name': 'reduction polynomial constants'},
    )
    a = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'a'},
    )
    d = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'd'},
    )
    x = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'x'},
    )
    y = attr.ib(  # pylint: disable=invalid-name
        converter=convert_extension_field_element(),
        validator=validate_extension_field_element(),
        metadata={'human_readable_name': 'y'},
    )
    n = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'n'},
    )
    h = attr.ib(  # pylint: disable=invalid-name
        converter=convert_big_enum(),
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'h'},
    )

    @classmethod
    def get_parameter_form(cls):
        return ECParameterForm.TWISTED_EDWARDS_EXTENSION


@attr.s(eq=False, frozen=True)
class ECParamWellKnownParams(ParamWellKnownBase, CryptoDataParamsOIDOptional):
    parameter_form = attr.ib(
        converter=convert_enum(ECParameterForm),
        validator=attr.validators.instance_of(ECParameterForm),
    )
    parameter_numbers = attr.ib(
        converter=convert_variadic((
            convert_dict_to_object(ECParameterNumbersWeierstrassPrime),
            convert_dict_to_object(ECParameterNumbersWeierstrassBinary),
            convert_dict_to_object(ECParameterNumbersWeierstrassBinaryNormalBasis),
            convert_dict_to_object(ECParameterNumbersMontgomery),
            convert_dict_to_object(ECParameterNumbersTwistedEdwards),
            convert_dict_to_object(ECParameterNumbersWeierstrassExtension),
            convert_dict_to_object(ECParameterNumbersTwistedEdwardsExtension),
        )),
        validator=attr.validators.instance_of((
            ECParameterNumbersWeierstrassPrime,
            ECParameterNumbersWeierstrassBinary,
            ECParameterNumbersWeierstrassBinaryNormalBasis,
            ECParameterNumbersMontgomery,
            ECParameterNumbersTwistedEdwards,
            ECParameterNumbersWeierstrassExtension,
            ECParameterNumbersTwistedEdwardsExtension,
        ))
    )

    @classmethod
    def get_gradeable_name(cls):
        return 'EC parameter'

    def __attrs_post_init__(self):
        if self.parameter_numbers.get_parameter_form() != self.parameter_form:
            raise InvalidValue(self.parameter_form, type(self), 'parameter_form')


class ECParamWellKnownBase(CryptoDataEnumOIDBase):
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


@attr.s(frozen=True)
class KeyEncapsulationMechanismParams(CryptoDataParamsNamed):
    standards = attr.ib(
        converter=convert_iterable(convert_enum(Standard)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(Standard))
    )
    papers = attr.ib(
        converter=convert_iterable(convert_enum(Paper)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(Paper))
    )
    encapsulation_key_size = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'encapsulation key size'},
    )
    decapsulation_key_size = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'decapsulation key size'},
    )
    ciphertext_size = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'ciphertext size'},
    )
    shared_secret_size = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'shared secret size'},
    )
    security_category = attr.ib(
        converter=convert_enum(NistSecurityLevel),
        validator=attr.validators.instance_of(NistSecurityLevel),
        metadata={'human_readable_name': 'security category'},
    )


class KeyEncapsulationMechanismBase(CryptoDataEnumBase):
    @classmethod
    def from_named_group(cls, named_group):
        try:
            key_encapsulation_mechanism = cls[named_group.name]
        except KeyError as e:
            raise InvalidValue(named_group, cls) from e

        return key_encapsulation_mechanism


KeyEncapsulationMechanism = KeyEncapsulationMechanismBase(
    'KeyEncapsulationMechanism', KeyEncapsulationMechanismBase.get_json_records(KeyEncapsulationMechanismParams)
)

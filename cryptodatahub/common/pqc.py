# SPDX-License-Identifier: MPL-2.0

import attr

from cryptodatahub.common.algorithm import NamedGroup, NistSecurityLevel
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.parameter import Paper, Standard
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataParamsNamed,
    convert_enum,
    convert_iterable,
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


@attr.s(frozen=True)
class HybridNamedGroupParams(CryptoDataParamsNamed):
    classical_named_group = attr.ib(
        converter=convert_enum(NamedGroup),
        validator=attr.validators.instance_of(NamedGroup),
    )
    post_quantum_named_group = attr.ib(
        converter=convert_enum(NamedGroup),
        validator=attr.validators.instance_of(NamedGroup),
    )


HybridNamedGroup = CryptoDataEnumBase(
    'HybridNamedGroup', CryptoDataEnumBase.get_json_records(HybridNamedGroupParams)
)

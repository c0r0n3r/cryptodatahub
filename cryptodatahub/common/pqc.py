# SPDX-License-Identifier: MPL-2.0

import attr

from cryptodatahub.common.algorithm import NistSecurityLevel
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import GradeableVulnerabilities
from cryptodatahub.common.parameter import ECParamWellKnown, ParamWellKnownBase
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataParamsNamed,
    convert_enum,
)


@attr.s(frozen=True)
class KeyEncapsulationMechanismParams(ParamWellKnownBase):
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
    oqs_name = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        metadata={'human_readable_name': 'Open Quantum Safe name', 'serialize_default': True},
    )

    @classmethod
    def get_gradeable_name(cls):
        return 'key encapsulation mechanism'


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
class HybridNamedGroupParams(CryptoDataParamsNamed, GradeableVulnerabilities):
    classical_key_parameter = attr.ib(
        converter=convert_enum(ECParamWellKnown),
        validator=attr.validators.instance_of(ECParamWellKnown),
    )
    post_quantum_key_parameter = attr.ib(
        converter=convert_enum(KeyEncapsulationMechanism),
        validator=attr.validators.instance_of(KeyEncapsulationMechanism),
    )
    oqs_name = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(str)),
        metadata={'human_readable_name': 'Open Quantum Safe name', 'serialize_default': True},
    )

    @classmethod
    def get_gradeable_name(cls):
        return 'hybrid named group'


HybridNamedGroup = CryptoDataEnumBase(
    'HybridNamedGroup', CryptoDataEnumBase.get_json_records(HybridNamedGroupParams)
)

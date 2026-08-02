# SPDX-License-Identifier: MPL-2.0

import attr

import cryptodatahub.common.algorithm
import cryptodatahub.tls.algorithm


@attr.s(frozen=True)
class FetchedNamedGroupParams(cryptodatahub.common.algorithm.NamedGroupParams):
    identifier = attr.ib(kw_only=True, validator=attr.validators.instance_of(str))

    def _asdict(self):
        as_dict = super()._asdict()
        as_dict.pop('identifier', None)

        return as_dict


@attr.s(frozen=True)
class FetchedNamedCurveParams(cryptodatahub.tls.algorithm.NamedCurveParams):
    identifier = attr.ib(kw_only=True, validator=attr.validators.instance_of(str))

    def _asdict(self):
        as_dict = super()._asdict()

        as_dict.pop('identifier', None)
        as_dict.pop('gradeables', None)

        as_dict['_code_in_hex'] = f'0x{self.code:04x}'
        as_dict.move_to_end('_code_in_hex', last=False)

        return as_dict


@attr.s(frozen=True)
class FetchedAuthenticationParams(cryptodatahub.common.algorithm.AuthenticationParams):
    identifier = attr.ib(kw_only=True, validator=attr.validators.instance_of(str))

    def _asdict(self):
        as_dict = super()._asdict()
        as_dict.pop('identifier', None)

        return as_dict


@attr.s(frozen=True)
class FetchedHashAndSignatureAlgorithmParams(cryptodatahub.tls.algorithm.HashAndSignatureAlgorithmParams):
    identifier = attr.ib(kw_only=True, validator=attr.validators.instance_of(str))

    def _asdict(self):
        as_dict = super()._asdict()

        as_dict.pop('identifier', None)
        as_dict.pop('gradeables', None)
        as_dict.pop('last_version', None)

        as_dict['_code_in_hex'] = f'0x{self.code:04x}'
        as_dict.move_to_end('_code_in_hex', last=False)

        return as_dict

#!/usr/bin/env python
# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import abc
import collections
import importlib
import itertools
import re

import attr
import yaml

import cryptodatahub.common.algorithm
import cryptodatahub.common.pqc
import cryptodatahub.tls.algorithm
import cryptodatahub.tls.version
from cryptodatahub.common.fetcher import FetcherBase
from cryptodatahub.common.utils import HttpFetcher, name_to_enum_item_name

from updaters.common import UpdaterBase
import updaters.oqs_datasheet
import updaters.oqs_params


@attr.s(frozen=True)
class OqsNamedGroup:
    code = attr.ib(validator=attr.validators.instance_of(int))
    name = attr.ib(validator=attr.validators.instance_of(str))
    size = attr.ib(validator=attr.validators.instance_of(int))
    oqs_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)))
    # The halves are the names of the entries a hybrid group is composed of, not the entries themselves: the
    # updater reloads the enum modules between its phases, so an enum member kept here would be an instance of a
    # class that no longer is the one the reloaded module defines. A group that has no classical half is not a
    # hybrid one.
    classical_key_parameter = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(str))
    )
    post_quantum_key_parameter = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(str))
    )

    @property
    def hybrid(self):
        return self.classical_key_parameter is not None


@attr.s(frozen=True)
class OqsAuthentication:
    identifier = attr.ib(validator=attr.validators.instance_of(str))
    name = attr.ib(validator=attr.validators.instance_of(str))
    long_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)))


@attr.s(frozen=True)
class OqsSignatureAlgorithm:
    code = attr.ib(validator=attr.validators.instance_of(int))
    name = attr.ib(validator=attr.validators.instance_of(str))
    authentication_identifier = attr.ib(validator=attr.validators.instance_of(str))
    authentication_name = attr.ib(validator=attr.validators.instance_of(str))
    authentication_long_name = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(str))
    )


class FetcherOqsBase(FetcherBase):
    _OQS_PROVIDER_VERSION = '0.11.0-rc1'
    _LIBOQS_VERSION = '0.15.0'
    _OQS_PROVIDER_CONFIG_URL = (
        'https://raw.githubusercontent.com/open-quantum-safe/oqs-provider/{version}/'
        'oqs-template/generate.yml'
    )
    _LIBOQS_ALGORITHM_DATASHEET_URL = (
        'https://raw.githubusercontent.com/open-quantum-safe/liboqs/{version}/'
        'docs/algorithms/kem/{name}.yml'
    )
    _OQS_ALGORITHM_NAME_PREFIX = 'OQS_KEM_alg_'
    _TLS_ENABLED_UP_TO_RELEASE_0_5 = True
    _DATASHEET_NAME_BY_FAMILY = {'CRYSTALS-Kyber': 'kyber'}
    _CLASSICAL_NAMED_CURVES = (
        cryptodatahub.tls.algorithm.TlsNamedCurve.SECP256R1,
        cryptodatahub.tls.algorithm.TlsNamedCurve.SECP384R1,
        cryptodatahub.tls.algorithm.TlsNamedCurve.SECP521R1,
    )
    _CLASSICAL_NAMED_CURVE_BY_HYBRID_GROUP_UP_TO_RELEASE_0_8_0 = {
        'p256': cryptodatahub.tls.algorithm.TlsNamedCurve.SECP256R1,
        'p384': cryptodatahub.tls.algorithm.TlsNamedCurve.SECP384R1,
    }
    _CLASSICAL_NAMED_CURVE_BY_HYBRID_GROUP = {
        **_CLASSICAL_NAMED_CURVE_BY_HYBRID_GROUP_UP_TO_RELEASE_0_8_0,
        'secp256_r1': cryptodatahub.tls.algorithm.TlsNamedCurve.SECP256R1,
        'secp384_r1': cryptodatahub.tls.algorithm.TlsNamedCurve.SECP384R1,
        'secp521_r1': cryptodatahub.tls.algorithm.TlsNamedCurve.SECP521R1,
        'bp256': cryptodatahub.tls.algorithm.TlsNamedCurve.BRAINPOOLP256R1,
        'bp384': cryptodatahub.tls.algorithm.TlsNamedCurve.BRAINPOOLP384R1,
        'bp512': cryptodatahub.tls.algorithm.TlsNamedCurve.BRAINPOOLP512R1,
        'x25519': cryptodatahub.tls.algorithm.TlsNamedCurve.X25519,
        'x448': cryptodatahub.tls.algorithm.TlsNamedCurve.X448,
    }

    @classmethod
    @abc.abstractmethod
    def _transform_data(cls, current_data):
        raise NotImplementedError()

    @classmethod
    def get_config_url(cls, version=None):
        return cls._OQS_PROVIDER_CONFIG_URL.format(version=version or cls._OQS_PROVIDER_VERSION)

    @classmethod
    def get_algorithm_datasheet_url(cls, name):
        return cls._LIBOQS_ALGORITHM_DATASHEET_URL.format(version=cls._LIBOQS_VERSION, name=name)

    @classmethod
    def _fetch_yaml(cls, url):
        return yaml.safe_load(HttpFetcher(connect_timeout=5, read_timeout=30)(url))

    @classmethod
    def _get_config(cls):
        return cls._fetch_yaml(cls.get_config_url())

    @staticmethod
    def _get_code(nid):
        nid = str(nid)

        return int(nid, 16) if nid.startswith('0x') else int(nid, 10)

    @staticmethod
    def _get_named_curve_size(named_curve):
        return named_curve.value.key_parameter.value.size

    @classmethod
    def _get_classical_named_curve(cls, bit_security):
        return min(
            (
                named_curve
                for named_curve in cls._CLASSICAL_NAMED_CURVES
                if cls._get_named_curve_size(named_curve) >= bit_security * 2
            ),
            key=cls._get_named_curve_size,
        )

    @classmethod
    def _get_hybrid_group(cls, named_curve):
        return f'p{cls._get_named_curve_size(named_curve)}'

    @classmethod
    def _get_datasheet_name(cls, family):
        return cls._DATASHEET_NAME_BY_FAMILY.get(family, family.lower().replace('-', '_'))

    @staticmethod
    def _get_comparable_algorithm_name(name):
        return name.replace('FrodoKEM', 'Frodo').lower().replace('_', '').replace('-', '')

    @classmethod
    def _is_tls_enabled(cls, key_encapsulation_mechanism):
        return key_encapsulation_mechanism.get('enable_tls', cls._TLS_ENABLED_UP_TO_RELEASE_0_5)

    @classmethod
    def _get_tls_enabled_key_encapsulation_mechanisms(cls, config):
        return list(filter(cls._is_tls_enabled, config['kems']))

    @classmethod
    def _get_algorithm_datasheets(cls, key_encapsulation_mechanisms):
        datasheets = collections.OrderedDict()
        for key_encapsulation_mechanism in key_encapsulation_mechanisms:
            datasheet_name = cls._get_datasheet_name(key_encapsulation_mechanism['family'])
            if datasheet_name not in datasheets:
                datasheets[datasheet_name] = cls._fetch_yaml(
                    cls.get_algorithm_datasheet_url(datasheet_name)
                )

        return datasheets

    @classmethod
    def _get_parameter_set(cls, datasheets, key_encapsulation_mechanism):
        datasheet = datasheets[cls._get_datasheet_name(key_encapsulation_mechanism['family'])]
        comparable_name = cls._get_comparable_algorithm_name(key_encapsulation_mechanism['name_group'])
        for parameter_set in datasheet['parameter-sets']:
            if cls._get_comparable_algorithm_name(parameter_set['name']) == comparable_name:
                return parameter_set

        return None

    @classmethod
    def _get_post_quantum_key_parameter(cls, key_encapsulation_mechanism, nist_round):
        """The plain entry a hybrid one of the same round is composed with.

        A round bearing entry is named after the algorithm for some families and
        after the group for others, so the candidates are resolved against the
        registry rather than one of the two spellings being assumed. None means
        the half cannot be named, and the composition is left unwritten.
        """
        name_group = key_encapsulation_mechanism['name_group']
        algorithm_name = key_encapsulation_mechanism['oqs_alg'][len(cls._OQS_ALGORITHM_NAME_PREFIX):]

        if nist_round is None:
            candidates = (name_group, algorithm_name)
        else:
            candidates = (f'{algorithm_name}_r{nist_round}', f'{name_group}_r{nist_round}')

        for candidate in candidates:
            identifier = name_to_enum_item_name(candidate)
            if identifier in cryptodatahub.common.algorithm.NamedGroup.__members__:
                return identifier

        return None

    @classmethod
    def _get_named_groups(cls, key_encapsulation_mechanism, bit_security, size):
        name_group = key_encapsulation_mechanism['name_group']

        if 'nid' in key_encapsulation_mechanism:
            yield OqsNamedGroup(
                code=cls._get_code(key_encapsulation_mechanism['nid']),
                name=name_group,
                size=size,
                oqs_name=name_group,
            )

        # Only this branch needs the strength, to choose a classical curve by it.
        # An entry whose parameter set the pinned release no longer describes still
        # names the classical half of every hybrid beside it outright.
        if 'nid_hybrid' in key_encapsulation_mechanism and bit_security is not None:
            classical_named_curve = cls._get_classical_named_curve(bit_security)
            yield OqsNamedGroup(
                code=cls._get_code(key_encapsulation_mechanism['nid_hybrid']),
                name=f'{classical_named_curve.name.lower()}/{name_group}',
                size=size,
                oqs_name=f'{cls._get_hybrid_group(classical_named_curve)}_{name_group}',
                classical_key_parameter=classical_named_curve.value.key_parameter.name,
                post_quantum_key_parameter=cls._get_post_quantum_key_parameter(
                    key_encapsulation_mechanism, None
                ),
            )

        extra_nids = key_encapsulation_mechanism.get('extra_nids', {})
        for extra_nid in itertools.chain(extra_nids.get('current', []), extra_nids.get('old', [])):
            yield cls._get_named_group_from_extra_nid(
                key_encapsulation_mechanism, extra_nid, size
            )

    @classmethod
    def _get_named_group_from_extra_nid(cls, key_encapsulation_mechanism, extra_nid, size):
        name_group = key_encapsulation_mechanism['name_group']
        named_group_name = key_encapsulation_mechanism['oqs_alg'][len(cls._OQS_ALGORITHM_NAME_PREFIX):]
        nist_round = extra_nid.get('nist-round')
        if nist_round is not None:
            named_group_name += f'_r{nist_round}'

        hybrid_group = extra_nid.get('hybrid_group')
        classical_key_parameter = None
        if hybrid_group is not None:
            classical_named_curve = cls._CLASSICAL_NAMED_CURVE_BY_HYBRID_GROUP[hybrid_group]
            classical_key_parameter = classical_named_curve.value.key_parameter.name
            named_group_name = f'{classical_named_curve.name.lower()}/{named_group_name}'

        is_earlier_nist_round = nist_round is not None
        repeats_plain_code_point = hybrid_group is None
        if is_earlier_nist_round or repeats_plain_code_point:
            oqs_name = None
        else:
            oqs_name = extra_nid.get('standard_name', f'{hybrid_group}_{name_group}')

        return OqsNamedGroup(
            code=cls._get_code(extra_nid['nid']),
            name=named_group_name,
            size=size,
            oqs_name=oqs_name,
            classical_key_parameter=classical_key_parameter,
            post_quantum_key_parameter=(
                None if classical_key_parameter is None
                else cls._get_post_quantum_key_parameter(key_encapsulation_mechanism, nist_round)
            ),
        )

    @classmethod
    def _get_current_data(cls):
        config = cls._get_config()
        key_encapsulation_mechanisms = cls._get_tls_enabled_key_encapsulation_mechanisms(config)
        datasheets = cls._get_algorithm_datasheets(key_encapsulation_mechanisms)

        oqs_named_groups = []
        for key_encapsulation_mechanism in key_encapsulation_mechanisms:
            parameter_set = cls._get_parameter_set(datasheets, key_encapsulation_mechanism)
            if parameter_set is None:
                continue

            nist_security_level = cryptodatahub.common.algorithm.NistSecurityLevel.from_code(
                parameter_set['claimed-nist-level']
            )
            oqs_named_groups.extend(cls._get_named_groups(
                key_encapsulation_mechanism,
                nist_security_level.value.bit_security,
                parameter_set['length-public-key'] * 8,
            ))

        return oqs_named_groups


class FetcherOqsSignatureAlgorithmBase(FetcherOqsBase):
    _AUTHENTICATION_BY_FAMILY = {
        'ML-DSA': OqsAuthentication(
            'MLDSA', 'ML-DSA', 'Module-Lattice-Based Digital Signature Algorithm'
        ),
        'Falcon': OqsAuthentication(
            'FALCON', 'Falcon', 'Fast-Fourier Lattice-based Compact Signatures over NTRU'
        ),
        'SPHINCS-SHA2': OqsAuthentication(
            'SLHDSA', 'SLH-DSA', 'Stateless Hash-Based Digital Signature Algorithm'
        ),
        'SPHINCS-SHAKE': OqsAuthentication(
            'SLHDSA', 'SLH-DSA', 'Stateless Hash-Based Digital Signature Algorithm'
        ),
        'MAYO': OqsAuthentication('MAYO', 'MAYO', None),
        'CROSS': OqsAuthentication(
            'CROSS', 'CROSS', 'Codes and Restricted Objects Signature Scheme'
        ),
        'UOV': OqsAuthentication('UOV', 'UOV', 'Unbalanced Oil and Vinegar'),
        'SNOVA': OqsAuthentication('SNOVA', 'SNOVA', None),
    }
    _PQCLEAN_IMPLEMENTATION_NAME = 'PQClean'

    @classmethod
    @abc.abstractmethod
    def _transform_data(cls, current_data):
        raise NotImplementedError()

    @classmethod
    def _is_pqclean_rebuild(cls, extra_nid):
        return cls._PQCLEAN_IMPLEMENTATION_NAME in extra_nid.get('implementation_version', '')

    @classmethod
    def _get_name_suffix(cls, extra_nid):
        nist_round = extra_nid.get('nist-round')
        name_suffix = '' if nist_round is None else f'_r{nist_round}'

        # Falcon carries both the round 3 submission and its PQClean rebuild under nist-round 3, and
        # upstream tells the two apart by the free text implementation_version only
        if cls._is_pqclean_rebuild(extra_nid):
            name_suffix += '_pqclean'

        return name_suffix

    @classmethod
    def _get_signature_algorithms(cls, family, variant):
        oqs_authentication = cls._AUTHENTICATION_BY_FAMILY[family]
        code_points = [('', variant['code_point'], variant.get('mix_with', []))]
        for extra_nid in variant.get('extra_nids', {}).get('old', []):
            code_points.append(
                (cls._get_name_suffix(extra_nid), extra_nid['code_point'], extra_nid.get('mix_with', []))
            )

        for name_suffix, code_point, mixed_algorithms in code_points:
            yield OqsSignatureAlgorithm(
                code=cls._get_code(code_point),
                name=f'{variant["name"]}{name_suffix}',
                authentication_identifier=oqs_authentication.identifier,
                authentication_name=oqs_authentication.name,
                authentication_long_name=oqs_authentication.long_name,
            )

            for mixed_algorithm in mixed_algorithms:
                composite_name = f'{mixed_algorithm["name"]}_{variant["name"]}'
                yield OqsSignatureAlgorithm(
                    code=cls._get_code(mixed_algorithm['code_point']),
                    name=f'{composite_name}{name_suffix}',
                    authentication_identifier=name_to_enum_item_name(composite_name),
                    authentication_name=f'{mixed_algorithm["pretty_name"]} + {variant["pretty_name"]}',
                    authentication_long_name=None,
                )

    @classmethod
    def _get_current_data(cls):
        oqs_signature_algorithms = []
        for family in cls._get_config()['sigs']:
            for variant in family.get('variants', []):
                if not variant.get('enable_tls'):
                    continue

                oqs_signature_algorithms.extend(cls._get_signature_algorithms(family['family'], variant))

        return oqs_signature_algorithms


class FetcherOqsNamedGroup(FetcherOqsBase):
    @staticmethod
    def _set_oqs_name(named_group_params, identifier, oqs_name):
        if oqs_name is None:
            return

        named_group_params[identifier] = attr.evolve(named_group_params[identifier], oqs_name=oqs_name)

    @classmethod
    def _transform_data(cls, current_data):
        named_group_params = collections.OrderedDict([
            (
                named_group.name,
                updaters.oqs_params.FetchedNamedGroupParams(
                    identifier=named_group.name, **named_group.value._asdict()
                ),
            )
            for named_group in cryptodatahub.common.algorithm.NamedGroup
        ])
        existing_names = {params.name for params in named_group_params.values()}
        existing_named_curves_by_code = collections.OrderedDict([
            (named_curve.value.code, named_curve)
            for named_curve in cryptodatahub.tls.algorithm.TlsNamedCurve
        ])

        for oqs_named_group in current_data:
            identifier = name_to_enum_item_name(oqs_named_group.name)

            existing_named_curve = existing_named_curves_by_code.get(oqs_named_group.code)
            if existing_named_curve is not None:
                if existing_named_curve.name != identifier:
                    print(
                        f'Code point already assigned; code=0x{oqs_named_group.code:04x}, '
                        f'existing={existing_named_curve.name}, fetched={identifier}'
                    )
                elif existing_named_curve.value.key_parameter is not None:
                    cls._set_oqs_name(
                        named_group_params,
                        existing_named_curve.value.key_parameter.name,
                        oqs_named_group.oqs_name,
                    )

                continue

            if oqs_named_group.name in existing_names:
                cls._set_oqs_name(named_group_params, identifier, oqs_named_group.oqs_name)

                continue

            named_group_params[identifier] = updaters.oqs_params.FetchedNamedGroupParams(
                identifier=identifier,
                name=oqs_named_group.name,
                long_name=None,
                oid=None,
                vulnerabilities=[],
                size=oqs_named_group.size,
                group_type=(
                    cryptodatahub.common.algorithm.NamedGroupType.HYBRID_PQS
                    if oqs_named_group.hybrid
                    else cryptodatahub.common.algorithm.NamedGroupType.POST_QUANTUM
                ),
                oqs_name=oqs_named_group.oqs_name,
            )
            existing_names.add(oqs_named_group.name)

        return list(named_group_params.values())


def _get_oqs_provider_release_order(version):
    release, _, candidate = version.partition('-rc')
    is_final_release = 0 if candidate else 1

    return tuple(map(int, release.split('.'))), is_final_release, int(candidate or 0)


class FetcherOqsHybridNamedGroup(FetcherOqsBase):
    # The first release that yields a group is the one that names it, and an algorithm carries no
    # round while it is current and gains one only once a later release retires it, so the oldest
    # naming would register secp256r1/kyber512 where the registry has secp256r1/kyber_512_r2.
    _OQS_PROVIDER_RETIRED_VERSIONS_NEWEST_FIRST = tuple(sorted(
        (
            '0.11.0', '0.10.0', '0.10.0-rc1', '0.9.0', '0.9.0-rc1', '0.8.0', '0.8.0-rc1',
            '0.7.0', '0.7.0-rc1', '0.6.1', '0.6.1-rc1', '0.6.0', '0.6.0-rc1',
            '0.5.3', '0.5.2', '0.5.1', '0.5.1-rc1', '0.5.0',
        ),
        key=_get_oqs_provider_release_order,
        reverse=True,
    ))

    @classmethod
    def _get_config_versions(cls):
        return (cls._OQS_PROVIDER_VERSION,) + cls._OQS_PROVIDER_RETIRED_VERSIONS_NEWEST_FIRST

    @classmethod
    def _get_family_nist_round(cls, datasheets, key_encapsulation_mechanism):
        datasheet = datasheets[cls._get_datasheet_name(key_encapsulation_mechanism['family'])]
        nist_round = datasheet.get('nist-round')

        return nist_round if isinstance(nist_round, int) else None

    @classmethod
    def _get_current_data(cls):
        oqs_named_groups = []
        for version in cls._get_config_versions():
            config = cls._fetch_yaml(cls.get_config_url(version))
            key_encapsulation_mechanisms = cls._get_tls_enabled_key_encapsulation_mechanisms(config)
            datasheets = cls._get_algorithm_datasheets(key_encapsulation_mechanisms)

            for key_encapsulation_mechanism in key_encapsulation_mechanisms:
                parameter_set = cls._get_parameter_set(datasheets, key_encapsulation_mechanism)
                bit_security = None
                if parameter_set is not None:
                    bit_security = cryptodatahub.common.algorithm.NistSecurityLevel.from_code(
                        parameter_set['claimed-nist-level']
                    ).value.bit_security

                oqs_named_groups.extend(cls._get_named_groups(
                    key_encapsulation_mechanism, bit_security, 0
                ))
                oqs_named_groups.extend(cls._get_named_groups_of_family_round(
                    key_encapsulation_mechanism,
                    bit_security,
                    cls._get_family_nist_round(datasheets, key_encapsulation_mechanism),
                ))

        return oqs_named_groups

    @classmethod
    def _get_named_groups_of_family_round(
            cls, key_encapsulation_mechanism, bit_security, family_nist_round
    ):
        if family_nist_round is None:
            return

        for oqs_named_group in cls._get_named_groups(key_encapsulation_mechanism, bit_security, 0):
            if not oqs_named_group.hybrid or oqs_named_group.name.endswith(f'_r{family_nist_round}'):
                continue

            yield attr.evolve(
                oqs_named_group,
                name=f'{oqs_named_group.name}_r{family_nist_round}',
                post_quantum_key_parameter=cls._get_post_quantum_key_parameter(
                    key_encapsulation_mechanism, family_nist_round
                ),
            )

    @classmethod
    def _transform_data(cls, current_data):
        hybrid_named_group_params = collections.OrderedDict([
            (
                hybrid_named_group.name,
                updaters.oqs_params.FetchedHybridNamedGroupParams(
                    identifier=hybrid_named_group.name, **hybrid_named_group.value._asdict()
                ),
            )
            for hybrid_named_group in cryptodatahub.common.pqc.HybridNamedGroup
        ])

        for oqs_named_group in current_data:
            if not oqs_named_group.hybrid:
                continue

            identifier = name_to_enum_item_name(oqs_named_group.name)
            if identifier in hybrid_named_group_params:
                continue

            # A composition describes a group the named group registry has. An entry whose code point is already
            # assigned never became one, so it must not gain a composition either, and neither half can be left
            # unnamed.
            named_group = cryptodatahub.common.algorithm.NamedGroup.__members__.get(identifier)
            if named_group is None or oqs_named_group.post_quantum_key_parameter is None:
                continue

            hybrid_named_group_params[identifier] = (
                updaters.oqs_params.FetchedHybridNamedGroupParams(
                    identifier=identifier,
                    # Taken from the named group registry rather than from the Open Quantum Safe name,
                    # which holds a standard name for a few entries and an internal one built from the
                    # two halves for the rest, so it is two kinds of thing under one field.
                    name=named_group.value.name,
                    long_name=named_group.value.long_name,
                    vulnerabilities=[],
                    classical_key_parameter=oqs_named_group.classical_key_parameter,
                    post_quantum_key_parameter=oqs_named_group.post_quantum_key_parameter,
                    oqs_name=oqs_named_group.name,
                )
            )

        return list(hybrid_named_group_params.values())


class FetcherOqsKeyEncapsulationMechanism(FetcherOqsBase):
    # Every release that documents its parameter sets, newest first. A round is
    # taken from the newest release still in it, because an older one may carry a
    # mistake a later release of the same round corrects: liboqs 0.5.0 claims NIST
    # level 1 for Kyber768-90s where 0.4.0 and 0.7.0 both claim 3.
    _LIBOQS_DATASHEET_VERSIONS = (
        '0.16.0', '0.15.0', '0.14.0', '0.13.0', '0.12.0', '0.11.0', '0.10.1', '0.10.0',
        '0.9.2', '0.9.1', '0.9.0', '0.8.0', '0.7.2', '0.7.1', '0.7.0',
    )
    # The releases before 0.7.0 state the same numbers in a table instead.
    _LIBOQS_MARKDOWN_DATASHEET_VERSIONS = ('0.6.0', '0.5.0', '0.4.0', '0.3.0')
    _LIBOQS_ALGORITHM_DATASHEET_MARKDOWN_URL = (
        'https://raw.githubusercontent.com/open-quantum-safe/liboqs/{version}/'
        'docs/algorithms/kem/{name}.md'
    )
    _DATASHEET_NAMES = ('bike', 'frodokem', 'hqc', 'kyber', 'ml_kem', 'ntru')

    @classmethod
    def get_algorithm_datasheet_markdown_url(cls, version, name):
        return cls._LIBOQS_ALGORITHM_DATASHEET_MARKDOWN_URL.format(version=version, name=name)

    @staticmethod
    def _split_nist_round(name):
        """A registry name carries the round it belongs to, a parameter set name does not.

        The separator is a hyphen in the stored records and an underscore in the
        named group names, so both are accepted.
        """
        match = re.search(r'[_-]r(\d)$', name)
        if match is None:
            return name, None

        return name[:match.start()], int(match.group(1))

    @classmethod
    def _get_datasheet_of_version(cls, version, datasheet_name, markdown):
        if markdown:
            content = HttpFetcher(connect_timeout=5, read_timeout=30)(
                cls.get_algorithm_datasheet_markdown_url(version, datasheet_name)
            )
            if isinstance(content, bytes):
                # The submitter names are not all spelled in ASCII.
                content = content.decode('utf-8')

            return (
                updaters.oqs_datasheet.get_nist_round_of_markdown(content),
                updaters.oqs_datasheet.get_parameter_sets_of_markdown(content),
            )

        datasheet = cls._fetch_yaml(
            cls._LIBOQS_ALGORITHM_DATASHEET_URL.format(version=version, name=datasheet_name)
        )

        return (
            updaters.oqs_datasheet.get_nist_round(datasheet),
            updaters.oqs_datasheet.get_parameter_sets(datasheet),
        )

    @classmethod
    def _get_datasheets_of_version(cls, version, markdown):
        datasheets = {}
        for datasheet_name in cls._DATASHEET_NAMES:
            try:
                nist_round, parameter_sets = cls._get_datasheet_of_version(
                    version, datasheet_name, markdown
                )
            except AttributeError:
                # A family that release does not describe. The fetcher leaves no
                # response behind for one, which is what reading it raises on.
                continue

            datasheets[datasheet_name] = (
                nist_round,
                {
                    cls._get_comparable_algorithm_name(name): parameter_set
                    for name, parameter_set in parameter_sets.items()
                },
            )

        return datasheets

    @classmethod
    def _get_current_data(cls):
        wanted = collections.OrderedDict(
            (named_group.name, cls._split_nist_round(named_group.value.name))
            for named_group in cryptodatahub.common.algorithm.NamedGroup
            if named_group.value.group_type
            == cryptodatahub.common.algorithm.NamedGroupType.POST_QUANTUM
        )

        resolved = collections.OrderedDict()
        versions = (
            [(version, False) for version in cls._LIBOQS_DATASHEET_VERSIONS] +
            [(version, True) for version in cls._LIBOQS_MARKDOWN_DATASHEET_VERSIONS]
        )
        for version, markdown in versions:
            if len(resolved) == len(wanted):
                break

            datasheets = cls._get_datasheets_of_version(version, markdown)
            for identifier, (name, nist_round) in wanted.items():
                if identifier in resolved:
                    continue

                comparable_name = cls._get_comparable_algorithm_name(name)
                for family_nist_round, parameter_sets in datasheets.values():
                    if comparable_name not in parameter_sets:
                        continue
                    # A datasheet that states its round has to agree, because a
                    # family can carry one parameter set name into two rounds with
                    # different sizes: Kyber512 encapsulates into 736 bytes in
                    # round 2 and 768 in round 3. Where a datasheet states no
                    # round the name is the only identity there is, and only the
                    # families that state one reuse a name across rounds.
                    if None not in (nist_round, family_nist_round) \
                            and family_nist_round != nist_round:
                        continue

                    parameter_set = parameter_sets[comparable_name]
                    # The round belongs in the name, the way the stored records
                    # spell it. Two rounds of one parameter set can hold the same
                    # sizes, and records that agree in every field are one record.
                    resolved[identifier] = attr.evolve(
                        parameter_set,
                        identifier=identifier,
                        name=(
                            parameter_set.name if nist_round is None
                            else f'{parameter_set.name}-r{nist_round}'
                        ),
                    )
                    break

        return list(resolved.values())

    @classmethod
    def _transform_data(cls, current_data):
        key_encapsulation_mechanism_params = collections.OrderedDict([
            (
                key_encapsulation_mechanism.name,
                updaters.oqs_params.FetchedKeyEncapsulationMechanismParams(
                    identifier=key_encapsulation_mechanism.name,
                    **key_encapsulation_mechanism.value._asdict()
                ),
            )
            for key_encapsulation_mechanism in cryptodatahub.common.pqc.KeyEncapsulationMechanism
        ])

        for parameter_set in current_data:
            existing = key_encapsulation_mechanism_params.get(parameter_set.identifier)
            # The sizes and the security category are what the datasheet states,
            # so they are taken from it even where a record already holds them.
            # The name, the aliases, the sources and the Open Quantum Safe name
            # are not in a datasheet at all — the last one is in the provider
            # configuration the hybrid compositions are read from — so a record
            # that has them keeps them.
            key_encapsulation_mechanism_params[parameter_set.identifier] = (
                updaters.oqs_params.FetchedKeyEncapsulationMechanismParams(
                    identifier=parameter_set.identifier,
                    name=existing.name if existing else parameter_set.name,
                    long_name=existing.long_name if existing else None,
                    vulnerabilities=existing.vulnerabilities if existing else [],
                    aliases=existing.aliases if existing else [],
                    sources=existing.sources if existing else [],
                    encapsulation_key_size=parameter_set.encapsulation_key_size,
                    decapsulation_key_size=parameter_set.decapsulation_key_size,
                    ciphertext_size=parameter_set.ciphertext_size,
                    shared_secret_size=parameter_set.shared_secret_size,
                    security_category=cryptodatahub.common.algorithm.NistSecurityLevel.from_code(
                        parameter_set.security_category
                    ),
                    oqs_name=existing.oqs_name if existing else None,
                )
            )

        return list(key_encapsulation_mechanism_params.values())


class FetcherOqsNamedCurve(FetcherOqsBase):
    @classmethod
    def _transform_data(cls, current_data):
        named_curve_params = []
        for named_curve in cryptodatahub.tls.algorithm.TlsNamedCurve:
            params = named_curve.value._asdict()
            params.pop('gradeables', None)
            named_curve_params.append(
                updaters.oqs_params.FetchedNamedCurveParams(identifier=named_curve.name, **params)
            )

        existing_codes = {params.code for params in named_curve_params}
        existing_identifiers = {params.identifier for params in named_curve_params}

        for oqs_named_group in current_data:
            if oqs_named_group.code in existing_codes:
                continue

            identifier = name_to_enum_item_name(oqs_named_group.name)
            if identifier in existing_identifiers:
                continue

            named_curve_params.append(updaters.oqs_params.FetchedNamedCurveParams(
                identifier=identifier,
                code=oqs_named_group.code,
                key_parameter=identifier,
                initial_version=cryptodatahub.tls.version.TlsVersion.TLS1_3,
                last_version=cryptodatahub.tls.version.TlsVersion.TLS1_3,
            ))
            existing_codes.add(oqs_named_group.code)
            existing_identifiers.add(identifier)

        return named_curve_params


class FetcherOqsAuthentication(FetcherOqsSignatureAlgorithmBase):
    @classmethod
    def _transform_data(cls, current_data):
        authentication_params = collections.OrderedDict([
            (
                authentication.name,
                updaters.oqs_params.FetchedAuthenticationParams(
                    identifier=authentication.name, **authentication.value._asdict()
                ),
            )
            for authentication in cryptodatahub.common.algorithm.Authentication
        ])

        for oqs_signature_algorithm in current_data:
            identifier = oqs_signature_algorithm.authentication_identifier
            if identifier in authentication_params:
                continue

            authentication_params[identifier] = updaters.oqs_params.FetchedAuthenticationParams(
                identifier=identifier,
                name=oqs_signature_algorithm.authentication_name,
                long_name=oqs_signature_algorithm.authentication_long_name,
                oid=None,
                vulnerabilities=[],
                anonymous=False,
            )

        return list(authentication_params.values())


class FetcherOqsSignatureAlgorithm(FetcherOqsSignatureAlgorithmBase):
    @classmethod
    def _transform_data(cls, current_data):
        signature_algorithm_params = collections.OrderedDict()
        for signature_algorithm in cryptodatahub.tls.algorithm.TlsSignatureAndHashAlgorithm:
            params = signature_algorithm.value._asdict()
            params.pop('gradeables', None)
            params.pop('last_version', None)
            signature_algorithm_params[signature_algorithm.name] = (
                updaters.oqs_params.FetchedHashAndSignatureAlgorithmParams(
                    identifier=signature_algorithm.name, **params
                )
            )

        existing_identifiers_by_code = collections.OrderedDict([
            (params.code, params.identifier) for params in signature_algorithm_params.values()
        ])

        for oqs_signature_algorithm in current_data:
            identifier = name_to_enum_item_name(oqs_signature_algorithm.name)

            existing_identifier = existing_identifiers_by_code.get(oqs_signature_algorithm.code)
            if existing_identifier is not None:
                if existing_identifier != identifier:
                    print(
                        f'Code point already assigned; code=0x{oqs_signature_algorithm.code:04x}, '
                        f'existing={existing_identifier}, fetched={identifier}'
                    )

                continue

            if identifier in signature_algorithm_params:
                print(
                    f'Identifier already in use; code=0x{oqs_signature_algorithm.code:04x}, '
                    f'identifier={identifier}'
                )

                continue

            signature_algorithm_params[identifier] = (
                updaters.oqs_params.FetchedHashAndSignatureAlgorithmParams(
                    identifier=identifier,
                    code=oqs_signature_algorithm.code,
                    hash_algorithm=None,
                    signature_algorithm=oqs_signature_algorithm.authentication_identifier,
                    initial_version=cryptodatahub.tls.version.TlsVersion.TLS1_3,
                )
            )
            existing_identifiers_by_code[oqs_signature_algorithm.code] = identifier

        return list(signature_algorithm_params.values())


class UpdaterOqsBase(UpdaterBase):
    @staticmethod
    def reload_enum_modules():  # pragma: no cover
        # The enum classes are built from the JSON data files at import time, so the named groups and
        # the authentication algorithms an updater writes can be referred to by the named curve and
        # the signature algorithm entries only after the modules defining those enum classes have
        # been imported again. Reloading them in a test would replace the enum classes the other
        # tests compare against, so this is only ever exercised by main().
        importlib.reload(cryptodatahub.common.algorithm)
        importlib.reload(cryptodatahub.common.pqc)
        importlib.reload(cryptodatahub.tls.algorithm)
        importlib.reload(updaters.oqs_params)


class UpdaterOqsNamedGroup(UpdaterOqsBase):
    def __init__(self):
        super().__init__(
            FetcherOqsNamedGroup,
            cryptodatahub.common.algorithm.NamedGroup,
            cryptodatahub.common.algorithm.NamedGroupParams,
        )

    @staticmethod
    def sort_key(merged_item):
        identifier, params = merged_item

        return params['group_type'], identifier


class UpdaterOqsHybridNamedGroup(UpdaterOqsBase):
    def __init__(self):
        super().__init__(
            FetcherOqsHybridNamedGroup,
            cryptodatahub.common.pqc.HybridNamedGroup,
            cryptodatahub.common.pqc.HybridNamedGroupParams,
        )


class UpdaterOqsKeyEncapsulationMechanism(UpdaterOqsBase):
    def __init__(self):
        super().__init__(
            FetcherOqsKeyEncapsulationMechanism,
            cryptodatahub.common.pqc.KeyEncapsulationMechanism,
            cryptodatahub.common.pqc.KeyEncapsulationMechanismParams,
        )


class UpdaterOqsNamedCurve(UpdaterOqsBase):
    def __init__(self):
        super().__init__(
            FetcherOqsNamedCurve,
            cryptodatahub.tls.algorithm.TlsNamedCurve,
            cryptodatahub.tls.algorithm.NamedCurveParams,
        )

    @staticmethod
    def sort_key(merged_item):
        _, params = merged_item

        return params['code']


class UpdaterOqsAuthentication(UpdaterOqsBase):
    def __init__(self):
        super().__init__(
            FetcherOqsAuthentication,
            cryptodatahub.common.algorithm.Authentication,
            cryptodatahub.common.algorithm.AuthenticationParams,
        )


class UpdaterOqsSignatureAlgorithm(UpdaterOqsBase):
    def __init__(self):
        super().__init__(
            FetcherOqsSignatureAlgorithm,
            cryptodatahub.tls.algorithm.TlsSignatureAndHashAlgorithm,
            cryptodatahub.tls.algorithm.HashAndSignatureAlgorithmParams,
        )

    @staticmethod
    def sort_key(merged_item):
        _, params = merged_item

        return params['code']


def main():
    UpdaterOqsNamedGroup()()  # pragma: no cover
    UpdaterOqsBase.reload_enum_modules()  # pragma: no cover
    UpdaterOqsKeyEncapsulationMechanism()()  # pragma: no cover
    UpdaterOqsBase.reload_enum_modules()  # pragma: no cover
    UpdaterOqsHybridNamedGroup()()  # pragma: no cover
    UpdaterOqsBase.reload_enum_modules()  # pragma: no cover
    UpdaterOqsNamedCurve()()  # pragma: no cover

    UpdaterOqsAuthentication()()  # pragma: no cover
    UpdaterOqsBase.reload_enum_modules()  # pragma: no cover
    UpdaterOqsSignatureAlgorithm()()  # pragma: no cover


if __name__ == '__main__':
    main()  # pragma: no cover

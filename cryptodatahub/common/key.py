# -*- coding: utf-8 -*-

import abc
import base64
import collections
import datetime
import os

from collections import OrderedDict

import asn1crypto.keys
import asn1crypto.pem
import asn1crypto.x509
import attr

from cryptodatahub.common.algorithm import Authentication, KeyExchange, Hash, NamedGroup, Signature
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import (
    AttackNamed,
    AttackType,
    Grade,
    GradeableComplex,
    GradeableVulnerabilities,
    Vulnerability,
)
from cryptodatahub.common.types import _ConverterBase
from cryptodatahub.common.utils import bytes_to_hex_string, hash_bytes

from cryptodatahub.tls.algorithm import TlsExtensionType


@attr.s(frozen=True)
class _PublicKeySizeGradeable(GradeableVulnerabilities):
    @classmethod
    def get_gradeable_name(cls):
        return 'public key size'


@attr.s(frozen=True)
class PublicKeySize(GradeableComplex):
    _FINITE_FIELD_TYPES = [Authentication.RSA, Authentication.DSS, KeyExchange.ADH, KeyExchange.DH, KeyExchange.DHE]
    _ELLIPTIC_CURVE_TYPES = [Authentication.ECDSA, Authentication.EDDSA, KeyExchange.ECDH, KeyExchange.ECDHE]

    key_type = attr.ib(validator=attr.validators.instance_of((Authentication, KeyExchange)))
    value = attr.ib(validator=attr.validators.instance_of(int))

    @value.validator
    def _value_validator(self, attribute, value):  # pylint: disable=unused-argument
        if value <= 0:
            raise InvalidValue(value, type(self), 'value')

    def __attrs_post_init__(self):
        if self.key_type in self._ELLIPTIC_CURVE_TYPES:
            gradeables = []
            attack_type = AttackType.DISCRETE_LOGARITHM
            if self.value <= 112:
                gradeables.append(Vulnerability(attack_type=attack_type, grade=Grade.INSECURE, named=None))
            elif self.value <= 160:
                gradeables.append(Vulnerability(attack_type=attack_type, grade=Grade.WEAK, named=None))
            gradeables = [_PublicKeySizeGradeable(gradeables)]
        elif self.key_type in self._FINITE_FIELD_TYPES:
            gradeables = []
            attack_type = AttackType.INTEGER_FACTORIZATION
            if self.value <= 768:
                if self.key_type == Authentication.RSA:
                    attack_named = AttackNamed.FREAK
                elif isinstance(self.key_type, KeyExchange):
                    attack_named = AttackNamed.WEAK_DH
                else:
                    attack_named = None

                gradeables.append(Vulnerability(attack_type=attack_type, grade=Grade.INSECURE, named=attack_named))
            elif self.value <= 1024:
                gradeables.append(Vulnerability(attack_type=attack_type, grade=Grade.WEAK, named=None))
            elif self.key_type in [KeyExchange.ADH, KeyExchange.DH, KeyExchange.DHE] and self.value > 4096:
                gradeables.append(
                    Vulnerability(attack_type=AttackType.DOS_ATTACK, grade=Grade.WEAK, named=AttackNamed.DHEAT_ATTACK)
                )
            gradeables = [_PublicKeySizeGradeable(gradeables)]
        elif self.key_type == KeyExchange.HYBRID_PQS:
            gradeables = []
        else:
            gradeables = None

        object.__setattr__(self, 'gradeables', gradeables)

    def __str__(self):
        return str(self.value)


@attr.s(repr=False, slots=True, hash=True)
class _PublicKeySizeConverter(_ConverterBase):
    key_exchange = attr.ib(validator=attr.validators.instance_of(KeyExchange))

    def __call__(self, value):
        if value is None:
            return None

        try:
            return PublicKeySize(self.key_exchange, value)
        except (TypeError, InvalidValue):
            return value

    def __repr__(self):
        return '<public key size converter>'


def convert_public_key_size(key_exchange):
    return _PublicKeySizeConverter(key_exchange)


@attr.s(frozen=True)
class PublicKeyParamBase():
    pass


@attr.s(frozen=True)
class PublicKeyParamsDsa(PublicKeyParamBase):
    prime = attr.ib(validator=attr.validators.instance_of(int))
    generator = attr.ib(validator=attr.validators.instance_of(int))
    order = attr.ib(validator=attr.validators.instance_of(int))
    public_key_value = attr.ib(validator=attr.validators.instance_of(int))


@attr.s(frozen=True)
class PublicKeyParamsEcdsa(PublicKeyParamBase):
    named_group = attr.ib(validator=attr.validators.instance_of(NamedGroup))
    point_x = attr.ib(validator=attr.validators.instance_of(int))
    point_y = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    def from_octet_bit_string(cls, named_group, octet_bit_string):
        point_x, point_y = asn1crypto.keys.ECPointBitString(bytes(octet_bit_string)).to_coords()
        return cls(
            named_group,
            point_x,
            point_y,
        )

    @property
    def octet_bit_string(self):
        return bytes(asn1crypto.keys.ECPointBitString.from_coords(self.point_x, self.point_y))


@attr.s(frozen=True)
class PublicKeyParamsEddsa(PublicKeyParamBase):
    curve_type = attr.ib(validator=attr.validators.instance_of(NamedGroup))
    key_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))


@attr.s(frozen=True)
class PublicKeyParamsRsa(PublicKeyParamBase):
    modulus = attr.ib(validator=attr.validators.instance_of(int))
    public_exponent = attr.ib(validator=attr.validators.instance_of(int))


@attr.s(eq=False, frozen=True)
class PublicKey():
    _public_key = attr.ib(validator=attr.validators.instance_of(asn1crypto.keys.PublicKeyInfo))

    @classmethod
    def from_der(cls, der):
        return cls(asn1crypto.keys.PublicKeyInfo.load(bytes(der)))

    @classmethod
    def from_pem(cls, pem):
        return cls.from_der(asn1crypto.pem.unarmor(pem.encode('ascii'))[2])

    @classmethod
    def from_pem_lines(cls, pem_lines):
        return cls.from_pem(os.linesep.join(pem_lines))

    @classmethod
    def from_params(cls, params):
        if isinstance(params, PublicKeyParamsDsa):
            algorithm_id = asn1crypto.keys.PublicKeyAlgorithmId('dsa')
            parameters = asn1crypto.keys.DSAParams({
                'p': params.prime, 'g': params.generator, 'q': params.order,
            })
            public_key = asn1crypto.keys.PublicKeyInfo({
                'algorithm': asn1crypto.keys.PublicKeyAlgorithm({
                    'algorithm': algorithm_id,
                    'parameters': parameters,
                }),
                'public_key': params.public_key_value,
            })
        elif isinstance(params, PublicKeyParamsEddsa):
            if params.curve_type == NamedGroup.CURVE25519:
                algorithm_name = 'ed25519'
            elif params.curve_type == NamedGroup.CURVE448:
                algorithm_name = 'ed448'
            else:
                raise NotImplementedError()

            algorithm_id = asn1crypto.keys.PublicKeyAlgorithmId(algorithm_name)
            public_key = asn1crypto.keys.PublicKeyInfo({
                'algorithm': asn1crypto.keys.PublicKeyAlgorithm({
                    'algorithm': algorithm_id,
                }),
                'public_key': asn1crypto.core.OctetBitString(bytes(params.key_data)),
            })
        elif isinstance(params, PublicKeyParamsRsa):
            algorithm_id = asn1crypto.keys.PublicKeyAlgorithmId('rsa')
            public_key = asn1crypto.keys.PublicKeyInfo({
                'algorithm': asn1crypto.keys.PublicKeyAlgorithm({'algorithm': algorithm_id}),
                'public_key': asn1crypto.keys.RSAPublicKey(
                    attr.asdict(params, recurse=False, value_serializer=None)
                )
            })
        elif isinstance(params, PublicKeyParamsEcdsa):
            algorithm_id = asn1crypto.keys.PublicKeyAlgorithmId('ec')
            parameters = asn1crypto.keys.ECDomainParameters({
                'named': params.named_group.value.oid
            })

            public_key = asn1crypto.keys.PublicKeyInfo({
                'algorithm': asn1crypto.keys.PublicKeyAlgorithm({
                    'algorithm': algorithm_id,
                    'parameters': parameters,
                }),
                'public_key': asn1crypto.keys.ECPointBitString.from_coords(params.point_x, params.point_y)
            })
        else:
            raise NotImplementedError(type(params))

        return cls(public_key)

    @property
    def params(self):
        if self.key_type == Authentication.DSS:
            public_key = self._public_key['public_key'].parsed
            parameters = self._public_key['algorithm']['parameters']
            return PublicKeyParamsDsa(
                prime=parameters['p'].native,
                generator=parameters['g'].native,
                order=parameters['q'].native,
                public_key_value=public_key.native,
            )
        if self.key_type == Authentication.ECDSA:
            public_key = self._public_key['public_key']
            parameters = self._public_key['algorithm']['parameters']

            return PublicKeyParamsEcdsa(
                NamedGroup.from_oid(parameters.chosen.dotted),
                *public_key.to_coords()
            )
        if self.key_type == Authentication.EDDSA:
            algorithm = self._public_key['algorithm']['algorithm']
            signature = Signature.from_oid(algorithm.dotted)
            if signature == Signature.ED25519:
                curve_type = NamedGroup.CURVE25519
            elif signature == Signature.ED448:
                curve_type = NamedGroup.CURVE448
            else:
                raise NotImplementedError()

            return PublicKeyParamsEddsa(
                curve_type=curve_type,
                key_data=self._public_key['public_key'].native
            )
        if self.key_type == Authentication.RSA:
            public_key = self._public_key['public_key'].parsed
            return PublicKeyParamsRsa(
                modulus=public_key['modulus'].native,
                public_exponent=public_key['public_exponent'].native,
            )

        raise NotImplementedError(self.key_type)

    @classmethod
    def _get_type_name(cls):
        return 'public key'

    def __eq__(self, other):
        return self.der == other.der

    @property
    def der(self):
        return self._public_key.dump()

    @property
    def pem(self):
        return asn1crypto.pem.armor(self._get_type_name().upper(), self.der).decode('utf-8')

    @property
    def key_type(self):
        try:
            key_type_oid = self._public_key['algorithm']['algorithm'].dotted
        except KeyError as e:
            key_type_oid = e.args[0]

        try:
            return Signature.from_oid(key_type_oid).value.key_type
        except InvalidValue:
            return Authentication.from_oid(key_type_oid)

    @property
    def key_size(self):
        if self.key_type == Authentication.GOST_R3410_12_256:
            return 256
        if self.key_type == Authentication.GOST_R3410_12_512:
            return 512
        if self.key_type == Authentication.GOST_R3410_01:
            return 256
        if self.key_type == Authentication.EDDSA:
            return self.params.curve_type.value.size

        return int(self._public_key.bit_size)

    @property
    def key_bytes(self):
        return PublicKey.der.fget(self)

    def get_digest(self, hash_type):
        return hash_bytes(hash_type, self.der)

    def fingerprint(self, hash_type):
        return bytes_to_hex_string(self.get_digest(hash_type), ':')

    @property
    def fingerprints(self):
        return OrderedDict([
            (hash_type, self.fingerprint(hash_type))
            for hash_type in [Hash.MD5, Hash.SHA1, Hash.SHA2_256]
        ])

    def _asdict(self):
        return collections.OrderedDict([
            ('algorithm', self.key_type),
            ('size', PublicKeySize(self.key_type, self.key_size)),
            ('fingerprints', self.fingerprints),
        ])


class PublicKeySigned(PublicKey):
    @property
    @abc.abstractmethod
    def valid_not_before(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def valid_not_after(self):
        raise NotImplementedError()

    @property
    def validity_period(self):
        return self.valid_not_after - self.valid_not_before

    @property
    def validity_remaining_time(self):
        now = datetime.datetime.now(asn1crypto.util.timezone.utc)
        return self.valid_not_after - now if now < self.valid_not_after else None

    @property
    def expired(self):
        return datetime.datetime.now(asn1crypto.util.timezone.utc) > self.valid_not_after

    @property
    @abc.abstractmethod
    def signature_hash_algorithm(self):
        raise NotImplementedError()


@attr.s(eq=False, init=False, frozen=True)
class PublicKeyX509Base(PublicKeySigned):  # pylint: disable=too-many-public-methods
    _EV_OIDS_BY_CA = {
        'A-Trust': ('1.2.40.0.17.1.22', ),
        'Actalis': ('1.3.159.1.17.1', ),
        'AffirmTrust': (
            '1.3.6.1.4.1.34697.2.1',
            '1.3.6.1.4.1.34697.2.2',
            '1.3.6.1.4.1.34697.2.3',
            '1.3.6.1.4.1.34697.2.4',
        ),
        'Buypass': ('2.16.578.1.26.1.3.3', ),
        'Camerfirma': (
            '1.3.6.1.4.1.17326.10.14.2.1.2',
            '1.3.6.1.4.1.17326.10.8.12.1.2',
        ),
        'Comodo Group': ('1.3.6.1.4.1.6449.1.2.1.5.1', ),
        'DigiCert': (
            '2.16.840.1.114412.1.3.0.2',
            '2.16.840.1.114412.2.1',
        ),
        'DigiNotar': ('2.16.528.1.1001.1.1.1.12.6.1.1.1', ),
        'E-Tugra': ('2.16.792.3.0.4.1.1.4', ),
        'ETSI': (
            '0.4.0.2042.1.4',
            '0.4.0.2042.1.5',
        ),
        'Entrust': ('2.16.840.1.114028.10.1.2', ),
        'Firmaprofesional': ('1.3.6.1.4.1.13177.10.1.3.10', ),
        'GeoTrust': ('1.3.6.1.4.1.14370.1.6', ),
        'GlobalSign': ('1.3.6.1.4.1.4146.1.1', ),
        'Go Daddy': ('2.16.840.1.114413.1.7.23.3', ),
        'Izenpe': ('1.3.6.1.4.1.14777.6.1.1', ),
        'Kamu Sertifikasyon Merkezi': ('2.16.792.1.2.1.1.5.7.1.9', ),
        'Logius PKIoverheid': ('2.16.528.1.1003.1.2.7', ),
        'Network Solutions': ('1.3.6.1.4.1.782.1.2.1.8.1', ),
        'OpenTrust/DocuSign France': ('1.3.6.1.4.1.22234.2.5.2.3.1', ),
        'QuoVadis': ('1.3.6.1.4.1.8024.0.2.100.1.2', ),
        'SECOM Trust Systems': ('1.2.392.200091.100.721.1', ),
        'SHECA': ('1.2.156.112570.1.1.3', ),
        'Starfield Technologies': ('2.16.840.1.114414.1.7.23.3', ),
        'StartCom Certification Authority': (
            '1.3.6.1.4.1.23223.1.1.1',
            '1.3.6.1.4.1.23223.2',
        ),
        'SwissSign': ('2.16.756.1.89.1.2.1.1', ),
        'Swisscom': ('2.16.756.1.83.21.0', ),
        'Symantec (VeriSign)': ('2.16.840.1.113733.1.7.23.6', ),
        'T-Systems': ('1.3.6.1.4.1.7879.13.24.1', ),
        'Thawte': ('2.16.840.1.113733.1.7.48.1', ),
        'Trustwave': ('2.16.840.1.114404.1.1.2.4.1', ),
        'Verizon Business (formerly Cybertrust)': ('1.3.6.1.4.1.6334.1.100.1', ),
        'Wells Fargo': ('2.16.840.1.114171.500.9', ),
        'WoSign': ('1.3.6.1.4.1.36305.2', ),
    }

    _certificate = attr.ib(validator=attr.validators.instance_of(asn1crypto.x509.Certificate))

    def __init__(self, certificate):
        super().__init__(certificate.public_key)

        object.__setattr__(self, '_certificate', certificate)

    @classmethod
    def _get_type_name(cls):
        return 'certificate'

    @classmethod
    def from_der(cls, der):
        return cls(asn1crypto.x509.Certificate.load(bytes(der)))

    @property
    def der(self):
        return self._certificate.dump()

    @property
    def valid_not_before(self):
        return self._certificate.not_valid_before

    @property
    def valid_not_after(self):
        return self._certificate.not_valid_after

    @property
    def signature_hash_algorithm(self):
        try:
            signature_oid = self._certificate['signature_algorithm']['algorithm'].dotted
        except KeyError as e:
            signature_oid = e.args[0]

        return Signature.from_oid(signature_oid)

    @property
    def public_key(self):
        return PublicKey(self._public_key)

    @property
    def public_key_pin(self):
        return base64.b64encode(hash_bytes(Hash.SHA2_256, self.key_bytes)).decode('ascii')

    def _has_any_policy_value(self, oid_values):
        if self._certificate.certificate_policies_value is None:
            return False

        for policy_information in self._certificate.certificate_policies_value:
            if policy_information['policy_identifier'].dotted in oid_values:
                return True

        return False

    @property
    def extended_validation(self):
        return any(map(self._has_any_policy_value, self._EV_OIDS_BY_CA.values()))

    @property
    def tls_features(self):
        tls_feature_value = self._certificate.tls_feature_value
        if tls_feature_value is None:
            return []

        return list(map(lambda feature: TlsExtensionType.from_code(feature.native), tls_feature_value))

    @property
    def serial_number(self):
        return self._certificate.serial_number

    @property
    def subject(self):
        return self._certificate.subject.native

    @property
    def issuer(self):
        return self._certificate.issuer.native

    @property
    def valid_domains(self):
        return self._certificate.valid_domains

    def is_subject_matches(self, host_name):
        return self._certificate.is_valid_domain_ip(host_name)

    @property
    def subject_alternative_names(self):
        if self._certificate.subject_alt_name_value is None:
            return []

        return self._certificate.subject_alt_name_value.native

    @property
    def crl_distribution_points(self):
        if self._certificate.crl_distribution_points_value is None:
            return []

        return [
            crl_distribution_point.url
            for crl_distribution_point in self._certificate.crl_distribution_points_value
        ]

    @property
    def ocsp_responders(self):
        return self._certificate.ocsp_urls

    @property
    def is_ca(self):
        return self._certificate.ca

    @property
    def is_self_signed(self):
        return self._certificate.self_issued

    def _asdict(self):
        items = [
            ('algorithm', self.key_type),
            ('size', PublicKeySize(self.key_type, self.key_size)),
            ('version', self._certificate['tbs_certificate']['version'].native),
            ('serial_number', str(self.serial_number)),
            ('subject', self.subject),
            ('subject_alternative_names', sorted(self.subject_alternative_names)),
            ('issuer', self.issuer),
            ('signature_hash_algorithm', self.signature_hash_algorithm),
            ('validity', collections.OrderedDict([
                ('not_before', str(self.valid_not_before)),
                ('not_after', str(self.valid_not_after)),
                ('period', str(self.validity_period)),
                ('remaining', str(self.validity_remaining_time.days) if self.validity_remaining_time else None),
            ])),
            ('revocation', collections.OrderedDict([
                ('crl_distribution_points', self.crl_distribution_points),
                ('ocsp_responders', self.ocsp_responders),
            ])),
            ('fingerprints', self.fingerprints),
            ('public_key_pin', self.public_key_pin),
        ]

        if not self.is_ca:
            items += [
                ('end_entity', collections.OrderedDict([
                    ('extended_validation', self.extended_validation),
                    ('tls_features', list(map(lambda feature: feature.name, self.tls_features))),
                ]))
            ]

        return collections.OrderedDict(items)

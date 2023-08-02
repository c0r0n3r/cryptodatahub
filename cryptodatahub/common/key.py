# -*- coding: utf-8 -*-

import abc
import hashlib
import base64
import datetime
import os

from collections import OrderedDict

import six
import asn1crypto.keys
import asn1crypto.pem
import asn1crypto.x509
import attr

from cryptodatahub.common.algorithm import Authentication, Hash, Signature
from cryptodatahub.common.utils import bytes_to_hex_string

from cryptodatahub.tls.algorithm import TlsExtensionType


@attr.s(eq=False)
class PublicKey(object):
    _HASHLIB_FUNCS = {
        Hash.MD5: hashlib.md5,
        Hash.SHA1: hashlib.sha1,
        Hash.SHA2_256: hashlib.sha256
    }

    _public_key = attr.ib(validator=attr.validators.instance_of(asn1crypto.keys.PublicKeyInfo))

    @classmethod
    def from_der(cls, der):
        return cls(asn1crypto.keys.PublicKeyInfo.load(der))

    @classmethod
    def from_pem(cls, pem):
        return cls.from_der(asn1crypto.pem.unarmor(pem.encode('ascii'))[2])

    @classmethod
    def from_pem_lines(cls, pem_lines):
        return cls.from_pem(os.linesep.join(pem_lines))

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
        return six.ensure_str(asn1crypto.pem.armor(six.u(self._get_type_name().upper()), self.der))

    @property
    def key_type(self):
        try:
            key_type_oid = self._public_key['algorithm']['algorithm'].dotted
        except KeyError as e:
            key_type_oid = e.args[0]

        return Authentication.from_oid(key_type_oid)

    @property
    def key_size(self):
        if self.key_type == Authentication.GOST_R3410_12_256:
            return 256
        if self.key_type == Authentication.GOST_R3410_12_512:
            return 512
        if self.key_type == Authentication.GOST_R3410_01:
            return 256

        return int(self._public_key.bit_size)

    @property
    def key_bytes(self):
        return PublicKey.der.fget(self)

    @classmethod
    def get_digest(cls, hash_type, key_bytes):
        try:
            hashlib_funcs = cls._HASHLIB_FUNCS[hash_type]
        except KeyError as e:
            six.raise_from(NotImplementedError(hash_type), e)

        return hashlib_funcs(key_bytes).digest()

    def fingerprint(self, hash_type):
        return bytes_to_hex_string(self.get_digest(hash_type, self.der), ':')

    @property
    def fingerprints(self):
        return OrderedDict([
            (hash_type, self.fingerprint(hash_type))
            for hash_type in [Hash.MD5, Hash.SHA1, Hash.SHA2_256]
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


@attr.s(eq=False, init=False)
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
        super(PublicKeySigned, self).__init__(certificate.public_key)

        self._certificate = certificate

    @classmethod
    def _get_type_name(cls):
        return 'certificate'

    @classmethod
    def from_der(cls, der):
        return cls(asn1crypto.x509.Certificate.load(der))

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
        return base64.b64encode(self.get_digest(Hash.SHA2_256, self.key_bytes)).decode('ascii')

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
        return OrderedDict([
            (six.ensure_str(name), value)
            for name, value in self._certificate.subject.native.items()
        ])

    @property
    def issuer(self):
        return self._certificate.issuer.native

    @property
    def valid_domains(self):
        return self._certificate.valid_domains

    def is_subject_matches(self, host_name):
        return self._certificate.is_valid_domain_ip(six.u(host_name))

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

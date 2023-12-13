# -*- coding: utf-8 -*-

import abc
import collections
import six

import attr

from cryptodatahub.common.algorithm import (
    Authentication,
    BlockCipher,
    BlockCipherMode,
    Hash,
    KeyExchange,
    MAC,
    NamedGroup,
)
from cryptodatahub.common.grade import GradeableComplex
from cryptodatahub.common.types import (
    CryptoDataEnumCodedBase,
    CryptoDataParamsEnumNumeric,
    CryptoDataParamsEnumString,
    CryptoDataParamsNamed,
    convert_enum,
)

from cryptodatahub.tls.version import TlsVersion


@attr.s(frozen=True)
class CompressionMethodParams(CryptoDataParamsNamed, CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 1


TlsCompressionMethod = CryptoDataEnumCodedBase(
    'TlsCompressionMethod', CryptoDataEnumCodedBase.get_json_records(CompressionMethodParams)
)


@attr.s(frozen=True)
class NamedCurveParams(CryptoDataParamsEnumNumeric, GradeableComplex):
    named_group = attr.ib(
        converter=convert_enum(NamedGroup),
        validator=attr.validators.optional(attr.validators.instance_of(NamedGroup)),
    )

    def __attrs_post_init__(self):
        if self.named_group is not None:
            object.__setattr__(self, 'gradeables', [self.named_group.value])

        attr.validate(self)

    def __str__(self):
        return str(self.named_group.value)

    @classmethod
    def get_code_size(cls):
        return 2


TlsNamedCurve = CryptoDataEnumCodedBase('TlsNamedCurve', CryptoDataEnumCodedBase.get_json_records(NamedCurveParams))


@attr.s(frozen=True)
class HashAndSignatureAlgorithmParams(CryptoDataParamsEnumNumeric, GradeableComplex):
    hash_algorithm = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.optional(attr.validators.instance_of(Hash)),
    )
    signature_algorithm = attr.ib(
        converter=convert_enum(Authentication),
        validator=attr.validators.optional(attr.validators.instance_of(Authentication)),
    )

    def __attrs_post_init__(self):
        vulnerabilities = []
        if self.hash_algorithm is not None:
            vulnerabilities.append(self.hash_algorithm.value)

        object.__setattr__(self, 'gradeables', vulnerabilities)

        attr.validate(self)

    def __str__(self):
        if self.hash_algorithm:
            hash_algorithm = self.hash_algorithm.value
        else:
            hash_algorithm = 'none'

        if self.signature_algorithm == Authentication.ANONYMOUS:
            signature_algorithm = 'no'
        else:
            signature_algorithm = self.signature_algorithm.value

        return '{} with {} encryption'.format(hash_algorithm, signature_algorithm)

    @classmethod
    def get_code_size(cls):
        return 2


TlsSignatureAndHashAlgorithm = CryptoDataEnumCodedBase(
    'TlsSignatureAndHashAlgorithm', CryptoDataEnumCodedBase.get_json_records(HashAndSignatureAlgorithmParams)
)


@attr.s(frozen=True)
class EcPointFormatParams(CryptoDataParamsNamed, CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 1


TlsECPointFormat = CryptoDataEnumCodedBase(
    'TlsECPointFormat', CryptoDataEnumCodedBase.get_json_records(EcPointFormatParams)
)


@attr.s(frozen=True)
class ProtocolNameParams(CryptoDataParamsEnumString):
    pass


TlsProtocolName = CryptoDataEnumCodedBase(
    'TlsProtocolName', CryptoDataEnumCodedBase.get_json_records(ProtocolNameParams)
)


@attr.s(frozen=True)
class NextProtocolNameParams(CryptoDataParamsEnumString):
    pass


TlsNextProtocolName = CryptoDataEnumCodedBase(
    'TlsNextProtocolName', CryptoDataEnumCodedBase.get_json_records(NextProtocolNameParams)
)


@attr.s(frozen=True)
class ExtensionTypeParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 2


TlsExtensionType = CryptoDataEnumCodedBase(
    'ExtensionType', CryptoDataEnumCodedBase.get_json_records(ExtensionTypeParams)
)


@attr.s(frozen=True)
class TokenBindingParamaterParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 1


TlsTokenBindingParamater = CryptoDataEnumCodedBase(
    'TlsTokenBindingParamater', CryptoDataEnumCodedBase.get_json_records(TokenBindingParamaterParams)
)


@attr.s(frozen=True)
class PskKeyExchangeModeParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 1


TlsPskKeyExchangeMode = CryptoDataEnumCodedBase(
    'TlsPskKeyExchangeMode', CryptoDataEnumCodedBase.get_json_records(PskKeyExchangeModeParams)
)


@attr.s(frozen=True)
class CertificateCompressionAlgorithmParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 2


TlsCertificateCompressionAlgorithm = CryptoDataEnumCodedBase(
    'TlsCertificateCompressionAlgorithm',
    CryptoDataEnumCodedBase.get_json_records(CertificateCompressionAlgorithmParams)
)


@attr.s(frozen=True)
class CipherParamsBase(CryptoDataParamsEnumNumeric, GradeableComplex):  # pylint: disable=too-many-instance-attributes
    iana_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    iana_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    openssl_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    key_exchange = attr.ib(
        converter=convert_enum(KeyExchange),
        validator=attr.validators.optional(attr.validators.instance_of(KeyExchange)),
    )
    authentication = attr.ib(
        converter=convert_enum(Authentication),
        validator=attr.validators.optional(attr.validators.instance_of(Authentication)),
    )
    bulk_cipher = attr.ib(
        converter=convert_enum(BlockCipher),
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipher)),
    )
    block_cipher_mode = attr.ib(
        converter=convert_enum(BlockCipherMode),
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode)),
    )
    mac = attr.ib(
        converter=convert_enum(MAC),
        validator=attr.validators.optional(attr.validators.instance_of(MAC)),
    )
    authenticated_encryption = attr.ib(validator=attr.validators.instance_of(bool))
    initial_version = attr.ib(
        converter=convert_enum(TlsVersion),
        validator=attr.validators.instance_of(TlsVersion),
    )
    last_version = attr.ib(init=False, validator=attr.validators.instance_of(TlsVersion))
    export_grade = attr.ib(init=False, validator=attr.validators.instance_of(bool))

    @classmethod
    @abc.abstractmethod
    def get_code_size(cls):
        raise NotImplementedError()

    def __attrs_post_init__(self):
        if self.initial_version == TlsVersion.SSL2:
            object.__setattr__(self, 'last_version', TlsVersion.SSL2)
        else:
            if self.code & 0xff00 in [0x1300, 0x7e00, 0x7f00]:
                object.__setattr__(self, 'last_version', TlsVersion.TLS1_3)
            else:
                object.__setattr__(self, 'last_version', TlsVersion.TLS1_2)

        object.__setattr__(self, 'export_grade', self.iana_name is not None and '_EXPORT' in self.iana_name)

        vulnerability_parts = collections.OrderedDict([
            (KeyExchange, self.key_exchange),
            (Authentication, self.authentication),
            (BlockCipher, self.bulk_cipher),
            (BlockCipherMode, self.block_cipher_mode),
            (MAC, self.mac),
        ])

        gradeables = []
        for algorithm in vulnerability_parts.values():
            if algorithm is None:
                continue

            gradeables.append(algorithm.value)

        object.__setattr__(self, 'gradeables', gradeables)

        attr.validate(self)

    def __str__(self):
        if self.iana_name is None:
            result = six.next(
                cipher_suite
                for cipher_suite in TlsCipherSuite
                if cipher_suite.value.code == self.code
            ).name
        else:
            result = self.iana_name

        if self.openssl_name:
            result += ' (' + self.openssl_name + ')'

        return result


@attr.s(frozen=True)
class CipherSuiteParams(CipherParamsBase):
    @classmethod
    def get_code_size(cls):
        return 2


TlsCipherSuite = CryptoDataEnumCodedBase('TlsCipherSuite', CryptoDataEnumCodedBase.get_json_records(CipherSuiteParams))


@attr.s(frozen=True)
class CipherKindParams(CipherParamsBase):
    @classmethod
    def get_code_size(cls):
        return 3


SslCipherKind = CryptoDataEnumCodedBase('SslCipherKind', CryptoDataEnumCodedBase.get_json_records(CipherKindParams))


class CipherSuiteExtensionParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 2


TlsCipherSuiteExtension = CryptoDataEnumCodedBase(
    'TlsCipherSuiteExtension', CryptoDataEnumCodedBase.get_json_records(CipherSuiteExtensionParams)
)


class GreaseOneByteParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 1


TlsGreaseOneByte = CryptoDataEnumCodedBase(
    'TlsGreaseOneByte', CryptoDataEnumCodedBase.get_json_records(GreaseOneByteParams)
)


class GreaseTwoByteParams(CryptoDataParamsEnumNumeric):
    @classmethod
    def get_code_size(cls):
        return 2


TlsGreaseTwoByte = CryptoDataEnumCodedBase(
    'TlsGreaseTwoByte', CryptoDataEnumCodedBase.get_json_records(GreaseTwoByteParams)
)

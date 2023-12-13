# -*- coding: utf-8 -*-

import abc
import enum
import attr

import six

from cryptodatahub.common.algorithm import (
    BlockCipher,
    BlockCipherMode,
    Hash,
    KeyExchange,
    MAC,
    MACMode,
    NamedGroup,
    Signature,
)
from cryptodatahub.common.grade import GradeableComplex, GradeableVulnerabilities
from cryptodatahub.common.key import PublicKeySize
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.common.types import (
    CryptoDataEnumCodedBase,
    CryptoDataParamsEnumString,
    convert_enum,
    convert_variadic,
)


@attr.s(frozen=True)
class SshAlgorithmParams(CryptoDataParamsEnumString, GradeableComplex):
    @property
    @abc.abstractmethod
    def _gradeable_algorithms(self):
        raise NotImplementedError()

    def __attrs_post_init__(self):
        gradeables = []
        for algorithm in self._gradeable_algorithms:
            if isinstance(algorithm, six.string_types):
                gradeable = getattr(self, algorithm)
                if gradeable is not None:
                    gradeable = gradeable.value
            else:
                gradeable = algorithm

            if gradeable is not None:
                gradeables.append(gradeable)

        object.__setattr__(self, 'gradeables', gradeables)

        attr.validate(self)


@attr.s(frozen=True)
class EncryptionAlgorithmParams(SshAlgorithmParams):
    cipher = attr.ib(
        converter=convert_enum(BlockCipher),
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipher))
    )
    mode = attr.ib(
        converter=convert_enum(BlockCipherMode),
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )

    @property
    def _gradeable_algorithms(self):
        return ('cipher', 'mode')


@attr.s(frozen=True)
class MacAlgorithmParams(SshAlgorithmParams):
    truncated_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))
    mac = attr.ib(
        converter=convert_enum(MAC),
        validator=attr.validators.optional(attr.validators.instance_of(MAC))
    )
    mode = attr.ib(
        converter=convert_enum(MACMode),
        validator=attr.validators.optional(attr.validators.instance_of(MACMode))
    )

    @property
    def size(self):
        if self.truncated_size is not None:
            return self.truncated_size

        return self.mac.value.digest_size

    @property
    def _gradeable_algorithms(self):
        return ('mac', 'mode')


@attr.s(frozen=True)
class KexAlgorithmParams(SshAlgorithmParams):
    kex = attr.ib(
        converter=convert_enum(KeyExchange),
        validator=attr.validators.optional(attr.validators.instance_of(KeyExchange))
    )
    key_parameter = attr.ib(
        converter=convert_variadic((convert_enum(NamedGroup), convert_enum(DHParamWellKnown))),
        validator=attr.validators.optional(
            attr.validators.instance_of((NamedGroup, DHParamWellKnown, six.string_types))
        )
    )
    exchange_hash = attr.ib(
        converter=convert_enum(Hash),
        validator=attr.validators.optional(attr.validators.instance_of(Hash))
    )
    key_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))

    def __attrs_post_init__(self):
        super(KexAlgorithmParams, self).__attrs_post_init__()

        if self.key_size is not None:
            gradeables = PublicKeySize(self.kex, self.key_size).gradeables
            if gradeables is None:
                self.gradeables.append(gradeables)
            else:
                self.gradeables.extend(gradeables)

        attr.validate(self)

    @property
    def _gradeable_algorithms(self):
        gradeables = ['kex', 'exchange_hash']

        if isinstance(self.key_parameter, DHParamWellKnown):
            gradeables.append(self.key_parameter.value)

        return gradeables


class SshHostKeyType(enum.Enum):
    HOST_KEY = 'host key'
    HOST_CERTIFICATE = 'host certificate'
    PGP_KEY = 'PGP key'
    SECURE_KEY = 'secure key'
    SECURE_CERTIFICATE = 'secure certificate'
    SPKI_KEY = 'SPKI key'
    X509_CERTIFICATE = 'X.509 certificate'
    X509_CERTIFICATE_CHAIN = 'X.509 certificate chain'


@attr.s(frozen=True)
class HostKeyAlgorithmParams(SshAlgorithmParams):
    key_type = attr.ib(
        converter=convert_enum(SshHostKeyType),
        validator=attr.validators.instance_of(SshHostKeyType)
    )
    signature = attr.ib(
        converter=convert_enum(Signature),
        validator=attr.validators.optional(attr.validators.instance_of(Signature))
    )

    @property
    def _gradeable_algorithms(self):
        return ('signature',)


@attr.s(frozen=True)
class CompressionAlgorithmParams(CryptoDataParamsEnumString, GradeableVulnerabilities):
    @classmethod
    def get_gradeable_name(cls):
        return 'compression'


@attr.s(frozen=True)
class EllipticCurveIdentifierParams(CryptoDataParamsEnumString):
    named_group = attr.ib(
        converter=convert_enum(NamedGroup),
        validator=attr.validators.instance_of(NamedGroup)
    )


SshEncryptionAlgorithm = CryptoDataEnumCodedBase(
    'SshEncryptionAlgorithm', CryptoDataEnumCodedBase.get_json_records(EncryptionAlgorithmParams)
)
SshMacAlgorithm = CryptoDataEnumCodedBase(
    'SshMacAlgorithm', CryptoDataEnumCodedBase.get_json_records(MacAlgorithmParams)
)
SshKexAlgorithm = CryptoDataEnumCodedBase(
    'SshKexAlgorithm', CryptoDataEnumCodedBase.get_json_records(KexAlgorithmParams)
)
SshHostKeyAlgorithm = CryptoDataEnumCodedBase(
    'SshHostKeyAlgorithm', CryptoDataEnumCodedBase.get_json_records(HostKeyAlgorithmParams)
)
SshCompressionAlgorithm = CryptoDataEnumCodedBase(
    'SshCompressionAlgorithm', CryptoDataEnumCodedBase.get_json_records(CompressionAlgorithmParams)
)
SshEllipticCurveIdentifier = CryptoDataEnumCodedBase(
    'SshEllipticCurveIdentifier', CryptoDataEnumCodedBase.get_json_records(EllipticCurveIdentifierParams)
)

# -*- coding: utf-8 -*-

import enum
import attr

import six

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, KeyExchange, MAC, NamedGroup, Signature
from cryptodatahub.common.types import CryptoDataEnumCodedBase, CryptoDataParamsEnumString, convert_enum


@attr.s
class MACModeParams(CryptoDataParamsEnumString):
    pass


class MACMode(enum.Enum):
    ENCRYPT_THEN_MAC = MACModeParams(
        code='encrypt_then_mac',
    )
    ENCRYPT_AND_MAC = MACModeParams(
        code='encrypt_and_mac',
    )
    MAC_THEN_ENCRYP = MACModeParams(
        code='mac_then_encrypt',
    )


@attr.s
class EncryptionAlgorithmParams(CryptoDataParamsEnumString):
    cipher = attr.ib(
        converter=convert_enum(BlockCipher),
        validator=attr.validators.optional(attr.validators.instance_of((BlockCipher, six.string_types)))
    )
    mode = attr.ib(
        converter=convert_enum(BlockCipherMode),
        validator=attr.validators.optional(attr.validators.instance_of((BlockCipherMode, six.string_types)))
    )


@attr.s
class MacAlgorithmParams(CryptoDataParamsEnumString):
    truncated_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))
    mac = attr.ib(
        converter=convert_enum(MAC),
        validator=attr.validators.optional(attr.validators.instance_of((MAC, six.string_types)))
    )
    mode = attr.ib(
        converter=convert_enum(MACMode),
        validator=attr.validators.optional(attr.validators.instance_of((MACMode, six.string_types)))
    )

    @property
    def size(self):
        if self.truncated_size is not None:
            return self.truncated_size

        return self.mac.value.digest_size


@attr.s
class KexAlgorithmParams(CryptoDataParamsEnumString):
    kex = attr.ib(
        converter=convert_enum(KeyExchange),
        validator=attr.validators.optional(attr.validators.instance_of((KeyExchange, six.string_types)))
    )
    key_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))


SshHostKeyType = enum.Enum('SshHostKeyType', 'KEY CERTIFICATE PGP_KEY SPKI_KEY X509_CERTIFICATE')


@attr.s
class HostKeyAlgorithmParams(CryptoDataParamsEnumString):
    key_type = attr.ib(
        converter=convert_enum(SshHostKeyType),
        validator=attr.validators.instance_of((SshHostKeyType, six.string_types))
    )
    signature = attr.ib(
        converter=convert_enum(Signature),
        validator=attr.validators.optional(attr.validators.instance_of((Signature, six.string_types)))
    )


@attr.s
class CompressionAlgorithmParams(CryptoDataParamsEnumString):
    pass


@attr.s
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

# -*- coding: utf-8 -*-

import enum
import attr

import six

from cryptodatahub.common.algorithm import Authentication, BlockCipher, BlockCipherMode, KeyExchange, MAC
from cryptodatahub.common.types import CryptoDataEnumCodedBase, CryptoDataParamsEnumString


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
    cipher = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((BlockCipher, six.string_types))))
    mode = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((BlockCipherMode, six.string_types))))

    def __attrs_post_init__(self):
        if isinstance(self.cipher, six.string_types):
            object.__setattr__(self, 'cipher', BlockCipher[self.cipher])

        if isinstance(self.mode, six.string_types):
            object.__setattr__(self, 'mode', BlockCipherMode[self.mode])


@attr.s
class MacAlgorithmParams(CryptoDataParamsEnumString):
    truncated_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))
    mac = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((MAC, six.string_types))))
    mode = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((MACMode, six.string_types))))

    def __attrs_post_init__(self):
        if isinstance(self.mac, six.string_types):
            object.__setattr__(self, 'mac', MAC[self.mac])

        if isinstance(self.mode, six.string_types):
            object.__setattr__(self, 'mode', MACMode[self.mode])

    @property
    def size(self):
        if self.truncated_size is not None:
            return self.truncated_size

        return self.mac.value.digest_size


@attr.s
class KexAlgorithmParams(CryptoDataParamsEnumString):
    kex = attr.ib(validator=attr.validators.optional(attr.validators.instance_of((KeyExchange, six.string_types))))
    key_size = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(int)))

    def __attrs_post_init__(self):
        if isinstance(self.kex, six.string_types):
            object.__setattr__(self, 'kex', KeyExchange[self.kex])


SshHostKeyType = enum.Enum('SshHostKeyType', 'KEY CERTIFICATE PGP_KEY SPKI_KEY X509_CERTIFICATE')


@attr.s
class HostKeyAlgorithmParams(CryptoDataParamsEnumString):
    key_type = attr.ib(validator=attr.validators.instance_of((SshHostKeyType, six.string_types)))
    authentication = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of((Authentication, six.string_types)))
    )

    def __attrs_post_init__(self):
        if isinstance(self.key_type, six.string_types):
            object.__setattr__(self, 'key_type', SshHostKeyType[self.key_type])

        if isinstance(self.authentication, six.string_types):
            object.__setattr__(self, 'authentication', Authentication[self.authentication])


@attr.s
class CompressionAlgorithmParams(CryptoDataParamsEnumString):
    pass


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

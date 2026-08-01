# SPDX-License-Identifier: MPL-2.0

import collections

import attr

from cryptodatahub.common.client import ClientParamsBase, get_client_capabilities_attribute
from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataParamsBase,
    HexData,
    convert_dict_to_object,
    convert_enum,
    convert_hex_data,
    convert_iterable,
)

from cryptodatahub.tls.algorithm import (
    TlsCertificateCompressionAlgorithm,
    TlsCipherSuite,
    TlsCompressionMethod,
    TlsECPointFormat,
    TlsExtensionType,
    TlsNamedCurve,
    TlsProtocolName,
    TlsPskKeyExchangeMode,
    TlsSignatureAndHashAlgorithm,
    TlsTokenBindingParamater,
)
from cryptodatahub.tls.version import TlsVersion


@attr.s(frozen=True)
class ClientTokenBindingParams(CryptoDataParamsBase):
    parameters = attr.ib(
        converter=convert_iterable(convert_enum(TlsTokenBindingParamater)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsTokenBindingParamater))
    )
    protocol_version = attr.ib(validator=attr.validators.instance_of(str))


@attr.s(frozen=True)
class ClientGreaseParams(CryptoDataParamsBase):
    cipher_suites = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    extension_types = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    extensions = attr.ib(
        default=[],
        converter=convert_iterable(convert_enum(TlsExtensionType)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsExtensionType))
    )


@attr.s(frozen=True)
class ClientExtensionParams(CryptoDataParamsBase):  # pylint: disable=too-many-instance-attributes
    application_layer_protocol_negotiation = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsProtocolName)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsProtocolName))
        )
    )
    application_layer_protocol_settings = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsProtocolName)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsProtocolName))
        )
    )
    compress_certificate = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsCertificateCompressionAlgorithm)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsCertificateCompressionAlgorithm))
        )
    )
    delegated_credentials = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsSignatureAndHashAlgorithm)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsSignatureAndHashAlgorithm))
        )
    )
    ec_point_formats = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsECPointFormat)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsECPointFormat))
        )
    )
    key_share = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsNamedCurve)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsNamedCurve))
        )
    )
    key_share_reserved = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsNamedCurve)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsNamedCurve))
        )
    )
    old_application_layer_protocol_settings = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsProtocolName)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsProtocolName))
        )
    )
    post_handshake_auth = attr.ib(default=None)
    psk_key_exchange_modes = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsPskKeyExchangeMode)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsPskKeyExchangeMode))
        )
    )
    record_size_limit = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))
    server_padding = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))
    signature_algorithms = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsSignatureAndHashAlgorithm)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsSignatureAndHashAlgorithm))
        )
    )
    supported_groups = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsNamedCurve)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsNamedCurve))
        )
    )
    supported_versions = attr.ib(
        default=None,
        converter=convert_iterable(convert_enum(TlsVersion)),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(TlsVersion))
        )
    )
    token_binding = attr.ib(
        default=None,
        converter=convert_dict_to_object(ClientTokenBindingParams),
        validator=attr.validators.optional(attr.validators.instance_of(ClientTokenBindingParams))
    )
    trust_anchors = attr.ib(
        default=None,
        converter=convert_iterable(convert_hex_data()),
        validator=attr.validators.optional(
            attr.validators.deep_iterable(attr.validators.instance_of(HexData))
        )
    )


@attr.s(frozen=True)
class ClientCapabilities(CryptoDataParamsBase):  # pylint: disable=too-many-instance-attributes
    tls_versions = attr.ib(
        converter=convert_iterable(convert_enum(TlsVersion)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsVersion))
    )
    cipher_suites = attr.ib(
        converter=convert_iterable(convert_enum(TlsCipherSuite)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsCipherSuite))
    )
    compression_methods = attr.ib(
        converter=convert_iterable(convert_enum(TlsCompressionMethod)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsCompressionMethod))
    )
    fallback_scsv = attr.ib(validator=attr.validators.instance_of(bool))
    empty_renegotiation_info_scsv = attr.ib(validator=attr.validators.instance_of(bool))
    grease = attr.ib(
        converter=convert_dict_to_object(ClientGreaseParams),
        validator=attr.validators.instance_of(ClientGreaseParams)
    )
    extension_types = attr.ib(
        converter=convert_iterable(convert_enum(TlsExtensionType)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsExtensionType))
    )
    extension_params = attr.ib(
        converter=convert_dict_to_object(ClientExtensionParams),
        validator=attr.validators.optional(attr.validators.instance_of(ClientExtensionParams))
    )

    def _asdict(self):
        capabilities_dict = attr.asdict(self, dict_factory=collections.OrderedDict)

        capabilities_dict['extension_params'] = collections.OrderedDict([
            (param_name, param_value)
            for param_name, param_value in capabilities_dict['extension_params'].items()
            if param_value is not None
        ])

        return capabilities_dict


@attr.s(frozen=True)
class ClientParams(ClientParamsBase):
    capabilities = get_client_capabilities_attribute(ClientCapabilities)


TlsClient = CryptoDataEnumBase('TlsClient', CryptoDataEnumBase.get_json_records(ClientParams))

# -*- coding: utf-8 -*-

from test.common.classes import TestClasses

from cryptodatahub.tls.algorithm import (
    SslCipherKind,
    TlsCertificateCompressionAlgorithm,
    TlsCipherSuite,
    TlsCipherSuiteExtension,
    TlsCompressionMethod,
    TlsECPointFormat,
    TlsExtensionType,
    TlsGreaseOneByte,
    TlsGreaseTwoByte,
    TlsNamedCurve,
    TlsNextProtocolName,
    TlsProtocolName,
    TlsPskKeyExchangeMode,
    TlsSignatureAndHashAlgorithm,
    TlsTokenBindingParamater,
)


class TestSslCipherKind(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return SslCipherKind


class TestTlsCertificateCompressionAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsCertificateCompressionAlgorithm


class TestTlsCipherSuite(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsCipherSuite

    def test_str(self):
        self.assertEqual(
            str(TlsCipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256.value),
            'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (ECDH-RSA-AES128-SHA256)'
        )
        self.assertEqual(
            str(TlsCipherSuite.TLS_ECDH_ECDSA_WITH_DES_CBC_SHA.value),
            'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA'
        )
        self.assertEqual(
            str(TlsCipherSuite.OLD_TLS_ECDH_ECDSA_WITH_NULL_SHA.value),
            'OLD_TLS_ECDH_ECDSA_WITH_NULL_SHA'
        )


class TestTlsCipherSuiteExtension(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsCipherSuiteExtension


class TestTlsCompressionMethod(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsCompressionMethod


class TestTlsECPointFormat(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsECPointFormat


class TestTlsExtensionType(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsExtensionType


class TestTlsGreaseOneByte(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsGreaseOneByte


class TestTlsGreaseTwoByte(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsGreaseTwoByte


class TestTlsNamedCurve(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsNamedCurve

    def test_str(self):
        self.assertEqual(str(TlsNamedCurve.X25519.value), 'Curve25519')


class TestTlsNextProtocolName(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return TlsNextProtocolName


class TestTlsProtocolName(TestClasses.TestJsonCodeStringBase):
    @classmethod
    def _get_class(cls):
        return TlsProtocolName


class TestTlsPskKeyExchangeMode(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsPskKeyExchangeMode


class TestTlsSignatureAndHashAlgorithm(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsSignatureAndHashAlgorithm

    def test_str(self):
        self.assertEqual(str(TlsSignatureAndHashAlgorithm.RSA_SHA1.value), 'SHA-1 with RSA encryption')


class TestTlsTokenBindingParamater(TestClasses.TestJsonCodeNumericBase):
    @classmethod
    def _get_class(cls):
        return TlsTokenBindingParamater

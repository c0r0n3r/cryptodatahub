# SPDX-License-Identifier: MPL-2.0

import contextlib
import io
import json
import unittest

from unittest import mock

import pyfakefs.fake_filesystem_unittest
import urllib3

import cryptodatahub.common.algorithm
from cryptodatahub.common.algorithm import (
    Authentication,
    AuthenticationParams,
    HybridNamedGroup,
    HybridNamedGroupParams,
    NamedGroup,
    NamedGroupParams,
    NamedGroupType,
    NistSecurityLevel,
)
from cryptodatahub.common.parameter import (
    KeyEncapsulationMechanism,
    KeyEncapsulationMechanismParams,
)
from cryptodatahub.common.types import CryptoDataEnumBase
from cryptodatahub.tls.algorithm import HashAndSignatureAlgorithmParams, NamedCurveParams
from cryptodatahub.tls.version import TlsVersion

from updaters.oqs import (
    FetcherOqsAuthentication,
    FetcherOqsBase,
    FetcherOqsHybridNamedGroup,
    FetcherOqsKeyEncapsulationMechanism,
    FetcherOqsNamedCurve,
    FetcherOqsNamedGroup,
    FetcherOqsSignatureAlgorithm,
    UpdaterOqsAuthentication,
    UpdaterOqsHybridNamedGroup,
    UpdaterOqsKeyEncapsulationMechanism,
    UpdaterOqsNamedCurve,
    UpdaterOqsNamedGroup,
    UpdaterOqsSignatureAlgorithm,
)
from updaters.oqs_params import (
    FetchedHybridNamedGroupParams,
    FetchedNamedCurveParams,
    FetchedNamedGroupParams,
)

HYBRID_NAMED_GROUP_HELD_BACK_SO_IT_IS_DERIVED = 'X448_KYBER_768_R3'
HYBRID_NAMED_GROUPS_LEFT_IN_THE_REGISTRY = [
    hybrid_named_group for hybrid_named_group in HybridNamedGroup
    if hybrid_named_group.name != HYBRID_NAMED_GROUP_HELD_BACK_SO_IT_IS_DERIVED
]

DATASHEET_NAMES = ('bike', 'frodokem', 'hqc', 'kyber', 'ml_kem', 'ntru')
MARKDOWN_DATASHEET_VERSION = '0.6.0'
MARKDOWN_DATASHEET_COLUMNS = (
    'Parameter set', 'Claimed NIST security level', 'Public key size (bytes)',
    'Secret key size (bytes)', 'Ciphertext size (bytes)', 'Shared secret size (bytes)',
)
MARKDOWN_KYBER_DATASHEET = '\n'.join([
    '# CRYSTALS-Kyber',
    '',
    '- **Version**: NIST Round 2 submission',
    '',
    '## Parameter sets',
    '',
    '| ' + ' | '.join(MARKDOWN_DATASHEET_COLUMNS) + ' |',
    '| ' + ' | '.join(['---'] * len(MARKDOWN_DATASHEET_COLUMNS)) + ' |',
    '| ' + ' | '.join(['Kyber512', '1', '800', '1632', '736', '32']) + ' |',
    # A row naming no parameter set.
    '| ' + ' | '.join(['', '1', '800', '1632', '736', '32']) + ' |',
    # A row stating something other than a number.
    '| ' + ' | '.join(['Kyber768', 'unstated', '1184', '2400', '1088', '32']) + ' |',
    # A row of a shape the heading does not describe.
    '| ' + ' | '.join(['Kyber1024', '5']) + ' |',
])
KYBER_PARAMETER_SET_DATASHEET = """
    nist-round: 3
    parameter-sets:
    - name: Kyber512
      claimed-nist-level: 1
      length-public-key: 800
      length-secret-key: 1632
      length-ciphertext: 768
      length-shared-secret: 32
"""
NTRU_PARAMETER_SET_DATASHEET = """
    nist-round: 3
    parameter-sets:
    - name: NTRU-HRSS-701
      claimed-nist-level: 3
      length-public-key: 1138
      length-secret-key: 1450
      length-ciphertext: 1138
      length-shared-secret: 32
    - name: NTRU-WITHOUT-A-CLAIMED-LEVEL
      length-public-key: 1138
      length-secret-key: 1450
      length-ciphertext: 1138
      length-shared-secret: 32
    - name: NTRU-WITHOUT-A-SIZE
      claimed-nist-level: 3
      length-public-key: 1138
"""
PARAMETER_SET_DATASHEET_BY_NAME = {
    'kyber': KYBER_PARAMETER_SET_DATASHEET,
    'ntru': NTRU_PARAMETER_SET_DATASHEET,
}
EMPTY_PARAMETER_SET_DATASHEET = 'parameter-sets: []'
EMPTY_MARKDOWN_DATASHEET = '# A family with no parameter set table'
KEY_ENCAPSULATION_MECHANISM_RESPONSES = dict(
    {
        FetcherOqsKeyEncapsulationMechanism.get_algorithm_datasheet_markdown_url(
            MARKDOWN_DATASHEET_VERSION, datasheet_name
        ): (
            MARKDOWN_KYBER_DATASHEET.encode('utf-8') if datasheet_name == 'kyber'
            else EMPTY_MARKDOWN_DATASHEET
        )
        for datasheet_name in DATASHEET_NAMES
    },
    **{
        FetcherOqsBase.get_algorithm_datasheet_url(datasheet_name):
            PARAMETER_SET_DATASHEET_BY_NAME.get(
                datasheet_name, EMPTY_PARAMETER_SET_DATASHEET
            )
        for datasheet_name in DATASHEET_NAMES
    },
)


class TestOqsBase(unittest.TestCase):
    ML_KEM_DATASHEET = """
        parameter-sets:
        - name: ML-KEM-512
          claimed-nist-level: 1
          length-public-key: 800
    """
    KYBER_DATASHEET = """
        parameter-sets:
        - name: Kyber512
          claimed-nist-level: 1
          length-public-key: 800
    """
    FRODOKEM_DATASHEET = """
        nist-round: 3
        parameter-sets:
        - name: FrodoKEM-640-AES
          claimed-nist-level: 1
          length-public-key: 9616
    """
    NON_EXISTING_ALGORITHM_DATASHEET = """
        parameter-sets:
        - name: NonExistingKEM
          claimed-nist-level: 1
          length-public-key: 42
        - name: HigherNistLevelKEM
          claimed-nist-level: 3
          length-public-key: 43
    """

    KEY_ENCAPSULATION_MECHANISM_LIST = """
        kems:"""
    ASSIGNED_CODE_POINT_NAMED_GROUP = """
          - family: 'ML-KEM'
            name_group: 'mlkem512'
            nid: '512'
            nid_hybrid: '0x2F4B'
            oqs_alg: 'OQS_KEM_alg_ml_kem_512'
            enable_tls: true
            extra_nids:
              current:
                - hybrid_group: 'x25519'
                  nid: '0x2FB6'
              old:
                - nist-round: 3
                  nid: '0x023A'
                - nist-round: 3
                  hybrid_group: 'secp256_r1'
                  nid: '0x2F3A'"""
    EXISTING_NAME_NAMED_GROUP = """
          - family: 'FrodoKEM'
            name_group: 'frodo640aes'
            oqs_alg: 'OQS_KEM_alg_frodokem_640_aes'
            enable_tls: true
            extra_nids:
              current:
                - hybrid_group: 'x25519'
                  nid: '0xFEF7'
              old:
                - nist-round: 3
                  hybrid_group: 'x25519'
                  nid: '0xFEFD'"""
    NON_EXISTING_NAMED_GROUP = """
          - family: 'NonExistingKEM'
            name_group: 'nonexistingkem'
            nid: '0xFEFE'
            nid_hybrid: '0xFEFF'
            oqs_alg: 'OQS_KEM_alg_non_existing_kem'
            enable_tls: true"""
    HIGHER_NIST_LEVEL_NAMED_GROUP = """
          - family: 'NonExistingKEM'
            name_group: 'highernistlevelkem'
            nid: '0xFEF0'
            nid_hybrid: '0xFEF1'
            oqs_alg: 'OQS_KEM_alg_higher_nist_level_kem'
            enable_tls: true"""
    WITHOUT_PARAMETER_SET_NAMED_GROUP = """
          - family: 'CRYSTALS-Kyber'
            name_group: 'withoutparametersetkyber'
            nid: '0xFEFC'
            oqs_alg: 'OQS_KEM_alg_without_parameter_set_kyber'
            enable_tls: true"""
    EARLIER_NIST_ROUND_NAMED_GROUP = """
          - family: 'CRYSTALS-Kyber'
            name_group: 'kyber512'
            oqs_alg: 'OQS_KEM_alg_kyber_512'
            enable_tls: true
            extra_nids:
              old:
                - nist-round: 3
                  nid: '0x023A'"""
    RETIRED_RELEASE_NAMED_GROUP = """
          - family: 'CRYSTALS-Kyber'
            name_group: 'kyber768'
            oqs_alg: 'OQS_KEM_alg_kyber_768'
            enable_tls: true
            extra_nids:
              old:
                - nist-round: 3
                  hybrid_group: 'x448'
                  nid: '0xFEF8'"""
    STORED_COMPOSITION_NAMED_GROUP = """
          - family: 'CRYSTALS-Kyber'
            name_group: 'kyber512'
            oqs_alg: 'OQS_KEM_alg_kyber_512'
            enable_tls: true
            extra_nids:
              old:
                - nist-round: 3
                  hybrid_group: 'x25519'
                  nid: '0xFEF9'"""
    TLS_DISABLED_NAMED_GROUP = """
          - family: 'TlsDisabledKEM'
            name_group: 'tlsdisabledkem'
            nid: '0xFEFB'
            oqs_alg: 'OQS_KEM_alg_tls_disabled_kem'
            enable_tls: false"""
    NON_EXISTING_NAMED_CURVE = """
          - family: 'ML-KEM'
            name_group: 'ml-kem-512'
            nid: '0xFEFE'
            oqs_alg: 'OQS_KEM_alg_ml_kem_512'
            enable_tls: true"""
    ASSIGNED_CODE_POINT_NAMED_CURVE = """
          - family: 'ML-KEM'
            name_group: 'ml-kem-512'
            nid_hybrid: '0x2F4B'
            oqs_alg: 'OQS_KEM_alg_ml_kem_512'
            enable_tls: true"""
    TAKEN_IDENTIFIER_NAMED_CURVE = """
          - family: 'ML-KEM'
            name_group: 'ml-kem-512'
            oqs_alg: 'OQS_KEM_alg_ml_kem_512'
            enable_tls: true
            extra_nids:
              current:
                - hybrid_group: 'x25519'
                  nid: '0xFEFF'"""

    KNOWN_SIGNATURE_ALGORITHM_FAMILY = """
        sigs:
          - family: 'MAYO'
            variants:"""
    COMPOSITE_SIGNATURE_ALGORITHM = """
              - name: 'nonexistingsig'
                pretty_name: 'Non-existing signature'
                code_point: '0xFFFB'
                enable_tls: true
                mix_with: [{'name': 'p256',
                            'pretty_name': 'ECDSA p256',
                            'code_point': '0xFFFC'}]"""
    NON_EXISTING_SIGNATURE_ALGORITHM = """
              - name: 'nonexistingsig'
                pretty_name: 'Non-existing signature'
                code_point: '0xFFFB'
                enable_tls: true
                extra_nids:
                  old:
                    - implementation_version: NIST Round 3 submission
                      nist-round: 3
                      code_point: '0xFFFD'
                    - implementation_version: PQClean Round 3 version labelled 20211101
                      nist-round: 3
                      code_point: '0xFFFE'
                    - implementation_version: NIST Round 3 submission
                      nist-round: 3
                      code_point: '0xFFFF'
                    - implementation_version: an entry without a NIST round
                      code_point: '0xFFF8'"""
    ASSIGNED_CODE_POINT_SIGNATURE_ALGORITHM = """
              - name: 'assignedcodepointsig'
                pretty_name: 'Assigned code point signature'
                code_point: '0x0401'
                enable_tls: true"""
    TLS_DISABLED_SIGNATURE_ALGORITHM = """
              - name: 'tlsdisabledsig'
                pretty_name: 'TLS disabled signature'
                code_point: '0xFFF9'
                enable_tls: false"""

    NAMED_GROUP_CONFIG = (
        KEY_ENCAPSULATION_MECHANISM_LIST +
        ASSIGNED_CODE_POINT_NAMED_GROUP +
        EXISTING_NAME_NAMED_GROUP +
        NON_EXISTING_NAMED_GROUP +
        HIGHER_NIST_LEVEL_NAMED_GROUP +
        WITHOUT_PARAMETER_SET_NAMED_GROUP +
        EARLIER_NIST_ROUND_NAMED_GROUP +
        STORED_COMPOSITION_NAMED_GROUP +
        TLS_DISABLED_NAMED_GROUP
    )
    NAMED_CURVE_CONFIG = (
        KEY_ENCAPSULATION_MECHANISM_LIST +
        NON_EXISTING_NAMED_CURVE +
        ASSIGNED_CODE_POINT_NAMED_CURVE +
        TAKEN_IDENTIFIER_NAMED_CURVE
    )
    AUTHENTICATION_CONFIG = (
        KNOWN_SIGNATURE_ALGORITHM_FAMILY +
        COMPOSITE_SIGNATURE_ALGORITHM +
        TLS_DISABLED_SIGNATURE_ALGORITHM
    )
    SIGNATURE_ALGORITHM_CONFIG = (
        KNOWN_SIGNATURE_ALGORITHM_FAMILY +
        NON_EXISTING_SIGNATURE_ALGORITHM +
        ASSIGNED_CODE_POINT_SIGNATURE_ALGORITHM +
        TLS_DISABLED_SIGNATURE_ALGORITHM
    )

    NAMED_GROUP_RESPONSES = {
        FetcherOqsBase.get_config_url(): NAMED_GROUP_CONFIG,
        FetcherOqsBase.get_algorithm_datasheet_url('ml_kem'): ML_KEM_DATASHEET,
        FetcherOqsBase.get_algorithm_datasheet_url('frodokem'): FRODOKEM_DATASHEET,
        FetcherOqsBase.get_algorithm_datasheet_url('nonexistingkem'): NON_EXISTING_ALGORITHM_DATASHEET,
        FetcherOqsBase.get_algorithm_datasheet_url('kyber'): KYBER_DATASHEET,
    }
    RETIRED_RELEASE_VERSION = '0.10.0'
    RETIRED_RELEASE_CONFIG = (
        KEY_ENCAPSULATION_MECHANISM_LIST +
        RETIRED_RELEASE_NAMED_GROUP
    )
    HYBRID_NAMED_GROUP_RESPONSES = dict(
        NAMED_GROUP_RESPONSES,
        **{FetcherOqsBase.get_config_url(RETIRED_RELEASE_VERSION): RETIRED_RELEASE_CONFIG},
    )
    NAMED_CURVE_RESPONSES = {
        FetcherOqsBase.get_config_url(): NAMED_CURVE_CONFIG,
        FetcherOqsBase.get_algorithm_datasheet_url('ml_kem'): ML_KEM_DATASHEET,
    }
    AUTHENTICATION_RESPONSES = {
        FetcherOqsBase.get_config_url(): AUTHENTICATION_CONFIG,
    }
    SIGNATURE_ALGORITHM_RESPONSES = {
        FetcherOqsBase.get_config_url(): SIGNATURE_ALGORITHM_CONFIG,
    }

    @staticmethod
    def get_mock_request(responses_by_url):
        def mock_request(_method, url, **_kwargs):
            if url not in responses_by_url:
                # What a release that does not carry the document does, rather
                # than an error of a kind the fetcher never sees.
                raise urllib3.exceptions.HTTPError(url)

            return urllib3.response.HTTPResponse(responses_by_url[url])

        return mock_request


class TestUpdaterOqsBase(TestOqsBase, pyfakefs.fake_filesystem_unittest.TestCase):
    def setUp(self):
        self.setUpPyfakefs()


class TestFetcherOqsNamedGroup(TestOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_named_group_parsing(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.NAMED_GROUP_RESPONSES)

        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            current_data = FetcherOqsNamedGroup.from_current_data()

        params_by_identifier = {params.identifier: params for params in current_data.parsed_data}

        self.assertEqual(
            params_by_identifier['NONEXISTINGKEM'],
            FetchedNamedGroupParams(
                identifier='NONEXISTINGKEM',
                name='nonexistingkem',
                long_name=None,
                oid=None,
                vulnerabilities=[],
                size=336,
                group_type=NamedGroupType.POST_QUANTUM,
                oqs_name='nonexistingkem',
            ),
        )
        self.assertEqual(
            params_by_identifier['SECP256R1_NONEXISTINGKEM'].name, 'secp256r1/nonexistingkem'
        )
        self.assertEqual(
            params_by_identifier['SECP256R1_NONEXISTINGKEM'].oqs_name, 'p256_nonexistingkem'
        )
        self.assertEqual(
            params_by_identifier['SECP256R1_NONEXISTINGKEM'].group_type, NamedGroupType.HYBRID_PQS
        )
        self.assertEqual(params_by_identifier['HIGHERNISTLEVELKEM'].size, 344)
        self.assertEqual(
            params_by_identifier['SECP384R1_HIGHERNISTLEVELKEM'].oqs_name, 'p384_highernistlevelkem'
        )
        self.assertEqual(params_by_identifier['MLKEM512'].oqs_name, 'mlkem512')
        self.assertEqual(params_by_identifier['X25519_ML_KEM_512'].oqs_name, 'x25519_mlkem512')
        self.assertEqual(params_by_identifier['KYBER_512_R3'].oqs_name, None)
        self.assertNotIn('WITHOUTPARAMETERSETKYBER', params_by_identifier)
        self.assertNotIn('TLSDISABLEDKEM', params_by_identifier)
        self.assertEqual(
            params_by_identifier['X25519_FRODOKEM_640_AES_R3'].size,
            NamedGroup.X25519_FRODOKEM_640_AES_R3.value.size,
        )
        self.assertEqual(
            report.getvalue().splitlines(),
            [
                'Code point already assigned; code=0x023a, existing=KYBER_512_R3, fetched=ML_KEM_512_R3',
                'Code point already assigned; code=0x2f3a, existing=SECP256R1_KYBER_512_R3, '
                'fetched=SECP256R1_ML_KEM_512_R3',
            ],
        )


class TestFetcherOqsHybridNamedGroup(TestOqsBase):
    @mock.patch.object(
        cryptodatahub.common.algorithm, 'HybridNamedGroup', HYBRID_NAMED_GROUPS_LEFT_IN_THE_REGISTRY
    )
    @mock.patch.object(
        FetcherOqsHybridNamedGroup, '_OQS_PROVIDER_RETIRED_VERSIONS_NEWEST_FIRST',
        (TestOqsBase.RETIRED_RELEASE_VERSION,),
    )
    def _get_params_by_identifier(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.HYBRID_NAMED_GROUP_RESPONSES)

        with contextlib.redirect_stdout(io.StringIO()):
            current_data = FetcherOqsHybridNamedGroup.from_current_data()

        return {params.identifier: params for params in current_data.parsed_data}

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_hybrid_named_group_parsing(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertEqual(
            params_by_identifier['X25519_ML_KEM_512'],
            FetchedHybridNamedGroupParams(
                identifier='X25519_ML_KEM_512',
                name=NamedGroup.X25519_ML_KEM_512.value.name,
                long_name=NamedGroup.X25519_ML_KEM_512.value.long_name,
                classical_named_group=NamedGroup.CURVE25519,
                post_quantum_named_group=NamedGroup.MLKEM512,
            ),
        )
        self.assertEqual(
            params_by_identifier['SECP256R1_MLKEM512'].classical_named_group,
            NamedGroup.PRIME256V1,
        )

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_round_bearing_half_is_found_under_either_spelling(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertEqual(
            params_by_identifier['X25519_FRODOKEM_640_AES_R3'].post_quantum_named_group,
            NamedGroup.FRODO640AES_R3,
        )

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_group_missing_from_the_named_group_registry_gets_no_composition(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertNotIn('SECP256R1_NONEXISTINGKEM', params_by_identifier)
        self.assertNotIn('SECP256R1_ML_KEM_512_R3', params_by_identifier)

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_group_only_a_retired_release_knows_is_derived(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertEqual(
            params_by_identifier[HYBRID_NAMED_GROUP_HELD_BACK_SO_IT_IS_DERIVED].post_quantum_named_group,
            NamedGroup.KYBER_768_R3,
        )

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_current_group_is_registered_again_under_the_round_of_its_family(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertEqual(
            params_by_identifier['X25519_FRODOKEM_640_AES_R3'].classical_named_group,
            NamedGroup.CURVE25519,
        )

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_plain_post_quantum_group_is_not_composed(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertNotIn('MLKEM512', params_by_identifier)

    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_stored_records_are_kept_as_they_are(self, mock_request):
        params_by_identifier = self._get_params_by_identifier(mock_request)

        self.assertEqual(
            params_by_identifier['CECPQ2'].name, HybridNamedGroup.CECPQ2.value.name
        )
        self.assertEqual(
            params_by_identifier['X25519_KYBER_512_R3'].name,
            HybridNamedGroup.X25519_KYBER_512_R3.value.name,
        )


class TestFetcherOqsKeyEncapsulationMechanism(TestOqsBase):
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_DATASHEET_NAMES',
        DATASHEET_NAMES + ('a_family_the_release_does_not_describe',),
    )
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_LIBOQS_DATASHEET_VERSIONS',
        (FetcherOqsBase._LIBOQS_VERSION,),  # pylint: disable=protected-access
    )
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_LIBOQS_MARKDOWN_DATASHEET_VERSIONS',
        (MARKDOWN_DATASHEET_VERSION,),
    )
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_key_encapsulation_mechanism_parsing(self, mock_request):
        mock_request.side_effect = self.get_mock_request(KEY_ENCAPSULATION_MECHANISM_RESPONSES)

        current_data = FetcherOqsKeyEncapsulationMechanism.from_current_data()
        params_by_identifier = {params.identifier: params for params in current_data.parsed_data}

        self.assertEqual(params_by_identifier['KYBER_512_R2'].ciphertext_size, 736 * 8)

        self.assertEqual(params_by_identifier['KYBER_512_R3'].encapsulation_key_size, 800 * 8)
        self.assertEqual(params_by_identifier['KYBER_512_R3'].shared_secret_size, 32 * 8)

        self.assertEqual(params_by_identifier['KYBER_512_R3'].ciphertext_size, 768 * 8)

        self.assertEqual(
            params_by_identifier['NTRU_HRSS_701'].security_category, NistSecurityLevel.LEVEL_3
        )
        self.assertEqual(
            params_by_identifier['NTRU_HRSS_701'].papers,
            KeyEncapsulationMechanism.NTRU_HRSS_701.value.papers,
        )
        self.assertEqual(
            params_by_identifier['NTRU_HRSS_701'].name,
            KeyEncapsulationMechanism.NTRU_HRSS_701.value.name,
        )
        self.assertEqual(params_by_identifier['KYBER_512_R2'].name, 'Kyber512-r2')
        self.assertIsNone(params_by_identifier['KYBER_512_R2'].long_name)


class TestFetcherOqsKeyEncapsulationMechanismResolvedEarly(TestOqsBase):
    @mock.patch.object(
        cryptodatahub.common.algorithm, 'NamedGroup', [NamedGroup.KYBER_512_R3]
    )
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_LIBOQS_DATASHEET_VERSIONS',
        (FetcherOqsBase._LIBOQS_VERSION,),  # pylint: disable=protected-access
    )
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_LIBOQS_MARKDOWN_DATASHEET_VERSIONS',
        (MARKDOWN_DATASHEET_VERSION,),
    )
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_releases_after_the_last_wanted_one_are_not_read(self, mock_request):
        mock_request.side_effect = self.get_mock_request(KEY_ENCAPSULATION_MECHANISM_RESPONSES)

        FetcherOqsKeyEncapsulationMechanism.from_current_data()

        read_urls = {call.args[1] for call in mock_request.call_args_list}
        self.assertTrue(any(
            FetcherOqsBase.get_algorithm_datasheet_url('kyber') == url for url in read_urls
        ))
        self.assertFalse(any('/0.6.0/' in url for url in read_urls))


class TestFetcherOqsNamedCurve(TestOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_named_curve_parsing(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.NAMED_CURVE_RESPONSES)

        current_data = FetcherOqsNamedCurve.from_current_data()
        params_by_identifier = {params.identifier: params for params in current_data.parsed_data}

        self.assertEqual(
            params_by_identifier['ML_KEM_512'],
            FetchedNamedCurveParams(
                identifier='ML_KEM_512',
                code=0xfefe,
                named_group=NamedGroup.ML_KEM_512,
                initial_version=TlsVersion.TLS1_3,
                last_version=TlsVersion.TLS1_3,
            ),
        )
        self.assertNotIn('SECP256R1_ML_KEM_512', params_by_identifier)
        self.assertEqual(params_by_identifier['SECP256R1_MLKEM512'].code, 0x2f4b)
        self.assertEqual(params_by_identifier['X25519_ML_KEM_512'].code, 0x2fb6)


class TestUpdaterOqsNamedGroup(TestUpdaterOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_named_group_update(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.NAMED_GROUP_RESPONSES)
        json_file_path = str(CryptoDataEnumBase.get_json_path(NamedGroupParams))
        self.fs.create_file(json_file_path, contents='{}')

        with contextlib.redirect_stdout(io.StringIO()):
            UpdaterOqsNamedGroup()()

        with open(json_file_path, encoding='ascii') as json_file:
            result = json.load(json_file)

        self.assertEqual(
            result['NONEXISTINGKEM'],
            {
                'name': 'nonexistingkem',
                'long_name': None,
                'oid': None,
                'vulnerabilities': [],
                'size': 336,
                'group_type': 'POST_QUANTUM',
                'oqs_name': 'nonexistingkem',
            },
        )

        sort_keys = [(params['group_type'], identifier) for identifier, params in result.items()]
        self.assertEqual(sort_keys, sorted(sort_keys))


class TestUpdaterOqsHybridNamedGroup(TestUpdaterOqsBase):
    @mock.patch.object(
        FetcherOqsHybridNamedGroup, '_OQS_PROVIDER_RETIRED_VERSIONS_NEWEST_FIRST',
        (TestUpdaterOqsBase.RETIRED_RELEASE_VERSION,),
    )
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_hybrid_named_group_update(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.HYBRID_NAMED_GROUP_RESPONSES)
        json_file_path = str(CryptoDataEnumBase.get_json_path(HybridNamedGroupParams))
        self.fs.create_file(json_file_path, contents='{}')

        with contextlib.redirect_stdout(io.StringIO()):
            UpdaterOqsHybridNamedGroup()()

        with open(json_file_path, encoding='ascii') as json_file:
            result = json.load(json_file)

        self.assertEqual(
            result['X25519_ML_KEM_512'],
            {
                'name': NamedGroup.X25519_ML_KEM_512.value.name,
                'long_name': None,
                'classical_named_group': 'CURVE25519',
                'post_quantum_named_group': 'MLKEM512',
            },
        )

        identifiers = list(result)
        self.assertEqual(identifiers, sorted(identifiers))


class TestUpdaterOqsKeyEncapsulationMechanism(TestUpdaterOqsBase):
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_LIBOQS_DATASHEET_VERSIONS',
        (FetcherOqsBase._LIBOQS_VERSION,),  # pylint: disable=protected-access
    )
    @mock.patch.object(
        FetcherOqsKeyEncapsulationMechanism, '_LIBOQS_MARKDOWN_DATASHEET_VERSIONS',
        (MARKDOWN_DATASHEET_VERSION,),
    )
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_key_encapsulation_mechanism_update(self, mock_request):
        mock_request.side_effect = self.get_mock_request(KEY_ENCAPSULATION_MECHANISM_RESPONSES)
        json_file_path = str(CryptoDataEnumBase.get_json_path(KeyEncapsulationMechanismParams))
        self.fs.create_file(json_file_path, contents='{}')

        UpdaterOqsKeyEncapsulationMechanism()()

        with open(json_file_path, encoding='ascii') as json_file:
            result = json.load(json_file)

        self.assertEqual(
            result['KYBER_512_R2'],
            {
                'name': 'Kyber512-r2',
                'long_name': None,
                'standards': [],
                'papers': [],
                'encapsulation_key_size': 800 * 8,
                'decapsulation_key_size': 1632 * 8,
                'ciphertext_size': 736 * 8,
                'shared_secret_size': 32 * 8,
                'security_category': 'LEVEL_1',
            },
        )
        self.assertEqual(result['NTRU_HRSS_701']['security_category'], 'LEVEL_3')

        identifiers = list(result)
        self.assertEqual(identifiers, sorted(identifiers))


class TestUpdaterOqsNamedCurve(TestUpdaterOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_named_curve_update(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.NAMED_CURVE_RESPONSES)
        json_file_path = str(CryptoDataEnumBase.get_json_path(NamedCurveParams))
        self.fs.create_file(json_file_path, contents='{}')

        UpdaterOqsNamedCurve()()

        with open(json_file_path, encoding='ascii') as json_file:
            result = json.load(json_file)

        self.assertEqual(
            result['ML_KEM_512'],
            {
                '_code_in_hex': '0xfefe',
                'code': 0xfefe,
                'named_group': 'ML_KEM_512',
                'initial_version': 'TLS1_3',
                'last_version': 'TLS1_3',
            },
        )

        codes = [params['code'] for params in result.values()]
        self.assertEqual(codes, sorted(codes))
        self.assertEqual(len(codes), len(set(codes)))


class TestFetcherOqsAuthentication(TestOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_authentication_parsing(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.AUTHENTICATION_RESPONSES)

        current_data = FetcherOqsAuthentication.from_current_data()
        params_by_identifier = {params.identifier: params for params in current_data.parsed_data}

        composite = params_by_identifier['P256_NONEXISTINGSIG']
        self.assertEqual(composite.name, 'ECDSA p256 + Non-existing signature')
        self.assertEqual(composite.long_name, None)
        self.assertEqual(composite.oid, None)
        self.assertEqual(composite.vulnerabilities, [])
        self.assertFalse(composite.anonymous)

        self.assertEqual(params_by_identifier['MAYO'].name, Authentication.MAYO.value.name)
        self.assertNotIn('TLSDISABLEDSIG', params_by_identifier)


class TestFetcherOqsSignatureAlgorithm(TestOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_signature_algorithm_parsing(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.SIGNATURE_ALGORITHM_RESPONSES)

        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            current_data = FetcherOqsSignatureAlgorithm.from_current_data()

        params_by_identifier = {params.identifier: params for params in current_data.parsed_data}

        self.assertEqual(params_by_identifier['NONEXISTINGSIG'].code, 0xfffb)
        self.assertEqual(
            params_by_identifier['NONEXISTINGSIG'].signature_algorithm, Authentication.MAYO
        )
        self.assertEqual(params_by_identifier['NONEXISTINGSIG'].hash_algorithm, None)
        self.assertEqual(params_by_identifier['NONEXISTINGSIG_R3'].code, 0xfffd)
        self.assertEqual(params_by_identifier['NONEXISTINGSIG_R3_PQCLEAN'].code, 0xfffe)
        self.assertNotIn('TLSDISABLEDSIG', params_by_identifier)
        self.assertEqual(
            report.getvalue().splitlines(),
            [
                'Identifier already in use; code=0xffff, identifier=NONEXISTINGSIG_R3',
                'Identifier already in use; code=0xfff8, identifier=NONEXISTINGSIG',
                'Code point already assigned; code=0x0401, existing=RSA_SHA256, '
                'fetched=ASSIGNEDCODEPOINTSIG',
            ],
        )


class TestUpdaterOqsAuthentication(TestUpdaterOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_authentication_update(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.AUTHENTICATION_RESPONSES)
        json_file_path = str(CryptoDataEnumBase.get_json_path(AuthenticationParams))
        self.fs.create_file(json_file_path, contents='{}')

        UpdaterOqsAuthentication()()

        with open(json_file_path, encoding='ascii') as json_file:
            result = json.load(json_file)

        self.assertEqual(
            result['P256_NONEXISTINGSIG'],
            {
                'name': 'ECDSA p256 + Non-existing signature',
                'long_name': None,
                'oid': None,
                'vulnerabilities': [],
                'anonymous': False,
            },
        )
        self.assertEqual(list(result), sorted(result))


class TestUpdaterOqsSignatureAlgorithm(TestUpdaterOqsBase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request')
    def test_signature_algorithm_update(self, mock_request):
        mock_request.side_effect = self.get_mock_request(self.SIGNATURE_ALGORITHM_RESPONSES)
        json_file_path = str(CryptoDataEnumBase.get_json_path(HashAndSignatureAlgorithmParams))
        self.fs.create_file(json_file_path, contents='{}')

        with contextlib.redirect_stdout(io.StringIO()):
            UpdaterOqsSignatureAlgorithm()()

        with open(json_file_path, encoding='ascii') as json_file:
            result = json.load(json_file)

        self.assertEqual(
            result['NONEXISTINGSIG'],
            {
                '_code_in_hex': '0xfffb',
                'code': 0xfffb,
                'hash_algorithm': None,
                'signature_algorithm': 'MAYO',
                'initial_version': 'TLS1_3',
            },
        )

        codes = [params['code'] for params in result.values()]
        self.assertEqual(codes, sorted(codes))

# SPDX-License-Identifier: MPL-2.0

import abc
import base64
import collections
import csv
import datetime
import io
import json
import tarfile

import attr
import bs4
import urllib3
import asn1crypto.core
import asn1crypto.pem
import asn1crypto.pkcs12
import asn1crypto.x509

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTransparencyLogParams,
    CertificateTransparencyLogTrustStore,
    CertificateTrustConstraint,
    RootCertificateParams,
    RootCertificateTrustConstraintAction,
    RootCertificateTrustStoreConstraint,
)
from cryptodatahub.common.stores import RootCertificate
from cryptodatahub.common.utils import HttpFetcher, name_to_enum_item_name


@attr.s
class HttpFetcherCrtShPem(HttpFetcher):
    @classmethod
    def get_retry_status_codes(cls):
        return super().get_retry_status_codes() | frozenset([404])


@attr.s(frozen=True)
class CertificatePemFetcher:
    http_fetcher = attr.ib(
        init=False,
        default=HttpFetcherCrtShPem(connect_timeout=5, read_timeout=30, retry=10),
        validator=attr.validators.instance_of(HttpFetcher),
    )

    def __call__(self, sha2_256_fingerprint):
        try:
            return RootCertificate.get_item_by_sha2_256_fingerprint(
                sha2_256_fingerprint
            ).value.certificate.pem
        except KeyError:
            data = self.http_fetcher(f'https://crt.sh/?d={sha2_256_fingerprint}')
            return data.decode('utf-8').strip()


@attr.s
class FetcherBase:
    """Abstract base class for all data fetchers.

    Subclasses must implement:
    - _get_current_data(): Fetch raw data from source
    - _transform_data(): Transform raw data into parsed format
    """
    parsed_data = attr.ib(validator=attr.validators.instance_of(collections.abc.Iterable))

    @classmethod
    @abc.abstractmethod
    def _get_current_data(cls):
        """Fetch raw data from the data source.

        Returns:
            Raw data in source-specific format
        """
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _transform_data(cls, current_data):
        """Transform raw data into parsed format.

        Args:
            current_data: Raw data from _get_current_data()

        Returns:
            Transformed/parsed data
        """
        raise NotImplementedError()

    @classmethod
    def from_current_data(cls):
        """Fetch and parse data from the source.

        Returns:
            Instance of the fetcher class with parsed_data populated
        """
        current_data = cls._get_current_data()
        transformed_data = cls._transform_data(current_data)

        return cls(transformed_data)


@attr.s
class _FetcherCertificateTransparencyLogStoreBase(FetcherBase):
    _CT_LOG_LIST_URL = None
    _INCLUDE_TILED_LOGS = False
    _TILED_LOG_EXTRA_FIELDS = ()
    _CT_LOG_OPERATOR_CANONICAL_NAME = {
        'Up In The Air Consulting': 'Filippo Valsorda',
        'Wang Shengnan': 'GDCA',
        'IPng GmbH': 'IPng Networks',
    }

    @classmethod
    def _get_current_data(cls):
        http = urllib3.PoolManager()
        response = http.request('GET', cls._CT_LOG_LIST_URL, preload_content=False)
        response.release_conn()

        return json.loads(response.data, object_pairs_hook=collections.OrderedDict)

    @classmethod
    def _transform_data(cls, current_data):
        per_log = collections.OrderedDict()

        for operator in current_data['operators']:
            operator_name = operator['name']
            operator_name = cls._CT_LOG_OPERATOR_CANONICAL_NAME.get(operator_name, operator_name)
            entries = list(operator.get('logs', []))
            if cls._INCLUDE_TILED_LOGS:
                for log in operator.get('tiled_logs', []):
                    pruned = collections.OrderedDict(
                        (k, v) for k, v in log.items()
                        if k not in cls._TILED_LOG_EXTRA_FIELDS
                    )
                    entries.append(pruned)
            for log in entries:
                log_state = None
                if 'state' in log:
                    state = log['state']
                    state_type = list(state)[0]
                    state_args = collections.OrderedDict([('state_type', state_type)])
                    state_args.update(state[state_type])
                    state_args.pop('final_tree_head', None)
                    state_args.pop('version', None)
                    log_state = state_args

                log_fields = collections.OrderedDict(log)
                log_fields.pop('state', None)
                log_fields['operator'] = Entity[name_to_enum_item_name(operator_name)].name

                per_log[log['log_id']] = (log_fields, log_state)

        return per_log


_TILED_LOG_EXTRA_FIELDS_COMMON = ('monitoring_url', 'submission_url', 'tls_only')


class FetcherCertificateTransparencyLogStoreGoogle(_FetcherCertificateTransparencyLogStoreBase):
    _CT_LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/all_logs_list.json'
    _INCLUDE_TILED_LOGS = True
    _TILED_LOG_EXTRA_FIELDS = _TILED_LOG_EXTRA_FIELDS_COMMON


class FetcherCertificateTransparencyLogStoreApple(_FetcherCertificateTransparencyLogStoreBase):
    _CT_LOG_LIST_URL = 'https://valid.apple.com/ct/log_list/current_log_list.json'
    _INCLUDE_TILED_LOGS = True
    _TILED_LOG_EXTRA_FIELDS = _TILED_LOG_EXTRA_FIELDS_COMMON


@attr.s
class FetcherCertificateTransparencyLogs(FetcherBase):
    _CT_LOG_STORE_UPDATERS = collections.OrderedDict([
        (Entity.GOOGLE, FetcherCertificateTransparencyLogStoreGoogle),
        (Entity.APPLE, FetcherCertificateTransparencyLogStoreApple),
    ])

    @classmethod
    def get_ct_log_store_updaters(cls):
        return cls._CT_LOG_STORE_UPDATERS

    @classmethod
    def _get_current_data(cls):
        return collections.OrderedDict([
            (store_owner, store_fetcher_class.from_current_data())
            for store_owner, store_fetcher_class in cls._CT_LOG_STORE_UPDATERS.items()
        ])

    @classmethod
    def _transform_data(cls, current_data):
        canonical_log_fields = collections.OrderedDict()
        trust_stores_per_log = collections.OrderedDict()

        for store_owner, store in current_data.items():
            for log_id, (log_fields, log_state) in store.parsed_data.items():
                if log_id not in canonical_log_fields:
                    canonical_log_fields[log_id] = log_fields
                trust_stores_per_log.setdefault(log_id, []).append(
                    CertificateTransparencyLogTrustStore(
                        owner=store_owner, log_state=log_state,
                    )
                )

        transformed_logs = []
        for log_id, log_fields in canonical_log_fields.items():
            trust_stores = tuple(sorted(
                trust_stores_per_log[log_id],
                key=lambda trust_store: trust_store.owner.name,
            ))
            transformed_logs.append(CertificateTransparencyLogParams(
                trust_stores=trust_stores, **log_fields,
            ))

        return transformed_logs


@attr.s
class FetcherCsvBase(FetcherBase):
    @classmethod
    @abc.abstractmethod
    def _get_csv_url(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_fetcher(cls):
        raise NotImplementedError()

    @classmethod
    def _get_current_data(cls):
        data = cls._get_fetcher()(cls._get_csv_url())
        return csv.DictReader(io.StringIO(data.decode('utf-8')))

    @classmethod
    @abc.abstractmethod
    def _transform_data(cls, current_data):
        """Transform CSV rows into parsed format.

        Args:
            current_data: CSV reader from _get_current_data()

        Returns:
            Transformed/parsed data
        """
        raise NotImplementedError()


class FetcherRootCertificateStoreAndroid(FetcherBase):
    _GITILES_REPO_BASE = 'https://android.googlesource.com/platform/system/ca-certificates'

    @classmethod
    def _get_current_commit_id(cls, fetcher):
        log_data = json.loads(
            fetcher(f'{cls._GITILES_REPO_BASE}/+log/refs/heads/main?n=1&format=JSON').lstrip(b")]}'\n")
        )
        return log_data['log'][0]['commit']

    @classmethod
    def _get_current_data(cls):
        # Configure fetcher with exponential backoff for 429 rate-limit responses
        fetcher = HttpFetcher(
            connect_timeout=5,
            read_timeout=30,
            retry=6,  # Allow 6 retries for rate limiting
            backoff_factor=1.0,  # Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s
        )
        commit_id = cls._get_current_commit_id(fetcher)
        commit_files_base = f'{cls._GITILES_REPO_BASE}/+/{commit_id}/files'

        listing = json.loads(
            fetcher(f'{commit_files_base}/?format=JSON').lstrip(b")]}'\n")
        )

        for entry in sorted(listing.get('entries', []), key=lambda entry: entry.get('name', '')):
            name = entry['name']
            raw = fetcher(f'{commit_files_base}/{name}?format=TEXT').strip()
            yield base64.b64decode(raw, validate=True).decode('ascii')

    @classmethod
    def _transform_data(cls, current_data):
        certificates = {}
        for root_certificate_pem in current_data:
            root_certificate_pem_lines = root_certificate_pem.splitlines()
            root_certificate_pem_lines = root_certificate_pem_lines[
                :root_certificate_pem_lines.index('-----END CERTIFICATE-----') + 1
            ]

            certificates[tuple(root_certificate_pem_lines)] = tuple()

        return certificates


class FetcherRootCertificateStoreChrome(FetcherBase):
    _GITILES_REPO_BASE = 'https://chromium.googlesource.com/chromium/src'
    _CHROME_ROOT_STORE_PATH = 'net/data/ssl/chrome_root_store/root_store.certs'

    @classmethod
    def _get_current_commit_id(cls, fetcher):
        log_data = json.loads(
            fetcher(f'{cls._GITILES_REPO_BASE}/+log/refs/heads/main?n=1&format=JSON').lstrip(b")]}'\n")
        )
        return log_data['log'][0]['commit']

    @classmethod
    def _get_current_data(cls):
        # Configure fetcher with exponential backoff for 429 rate-limit responses
        fetcher = HttpFetcher(
            connect_timeout=5,
            read_timeout=30,
            retry=6,
            backoff_factor=1.0,
        )
        commit_id = cls._get_current_commit_id(fetcher)
        url = (
            f'{cls._GITILES_REPO_BASE}/+/{commit_id}/{cls._CHROME_ROOT_STORE_PATH}'
            f'?format=TEXT'
        )

        raw = base64.b64decode(fetcher(url), validate=True)

        if b'-----BEGIN' not in raw:
            return

        for type_name, _headers, der_bytes in asn1crypto.pem.unarmor(raw, multiple=True):
            if type_name == 'CERTIFICATE':
                yield asn1crypto.pem.armor('CERTIFICATE', der_bytes).decode('ascii')

    @classmethod
    def _transform_data(cls, current_data):
        certificates = {}
        for root_certificate_pem in current_data:
            root_certificate_pem_lines = root_certificate_pem.splitlines()
            root_certificate_pem_lines = root_certificate_pem_lines[
                :root_certificate_pem_lines.index('-----END CERTIFICATE-----') + 1
            ]

            certificates[tuple(root_certificate_pem_lines)] = tuple()

        return certificates


class FetcherRootCertificateStoreApple(FetcherBase):
    FIELDS = (
        'Certificate name',
        'Issued by',
        'Type',
        'Key size',
        'Sig alg',
        'Serial number',
        'Expires',
        'EV policy',
        'Fingerprint (SHA-256)',
    )

    @classmethod
    def _get_current_data(cls):
        response = HttpFetcher()('https://support.apple.com/en-us/103254')
        page = bs4.BeautifulSoup(response.decode('utf-8'), 'html.parser')
        trusted_cas = page.find("h2", {"id": "trusted"})
        return [
            dict(zip(cls.FIELDS, map(lambda value: value.text.strip(), row.find_all('td'))))
            for row in trusted_cas.find_next('tbody').find_all('tr')[1:]
        ]

    @classmethod
    def _transform_data(cls, current_data):
        certificate_pem_fetcher = CertificatePemFetcher()
        certificates = {}
        for row in current_data:
            sha2_256_fingerprint = row['Fingerprint (SHA-256)'].replace(' ', '')
            root_certificate_pem = certificate_pem_fetcher(sha2_256_fingerprint)
            certificates[tuple(root_certificate_pem.splitlines())] = ()

        return certificates


class FetcherRootCertificateStoreMicrosoft(FetcherCsvBase):
    CSV_FIELDS = ('PEM',)

    @classmethod
    def _get_csv_url(cls):
        return (
            'https://ccadb.my.salesforce-sites.com/microsoft/IncludedRootsPEMCSVForMSFT'
            '?MicrosoftEKUs=Server%20Authentication'
        )

    @classmethod
    def _get_fetcher(cls):
        return HttpFetcher()

    @classmethod
    def _transform_data(cls, current_data):
        certificates = {}

        for row in current_data:
            root_certificate_pem = row.get('PEM', '').strip('\'').strip()
            certificates[tuple(root_certificate_pem.splitlines())] = tuple()

        return certificates


class FetcherRootCertificateStoreMozilla(FetcherCsvBase):
    CSV_FIELDS = ('PEM', 'Distrust for TLS After Date', 'Mozilla Applied Constraints')

    @classmethod
    def _get_csv_url(cls):
        return \
            'https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsDistrustTLSSSLPEMCSV?TrustBitsInclude=Websites'

    @classmethod
    def _get_fetcher(cls):
        return HttpFetcher()

    @classmethod
    def _transform_data(cls, current_data):
        certificates = {}

        for row in current_data:
            constraints = []

            distrust_after = row['Distrust for TLS After Date']
            if distrust_after:
                constraint = CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    date=datetime.datetime.strptime(distrust_after, '%Y.%m.%d'),
                )
                constraints.append(constraint)

            domain = row['Mozilla Applied Constraints']
            if domain:
                constraint = CertificateTrustConstraint(
                    action=RootCertificateTrustConstraintAction.DISTRUST,
                    domains=[domain],
                )
                constraints.append(constraint)

            root_certificate_pem_lines = tuple(row['PEM'].strip('\'').splitlines())
            certificates[root_certificate_pem_lines] = tuple(constraints)

        return certificates


class _FetcherRootCertificateStoreJDKBase(FetcherBase):
    _CACERTS_PATH_SUFFIX = '/lib/security/cacerts'

    @classmethod
    @abc.abstractmethod
    def _get_current_data(cls):
        raise NotImplementedError()

    @classmethod
    def _transform_data(cls, current_data):
        pfx = asn1crypto.pkcs12.Pfx.load(current_data)
        certificates = {}
        for content_info in pfx.authenticated_safe:
            if content_info['content_type'].native != 'data':
                raise NotImplementedError()

            safe_contents = asn1crypto.pkcs12.SafeContents.load(
                content_info['content'].native
            )
            for bag in safe_contents:
                if bag['bag_id'].native != 'cert_bag':
                    raise NotImplementedError()

                cert = bag['bag_value']['cert_value']

                # Unwrap the explicit [0] tag if it is encapsulated in an Any wrapper
                inner = cert.parsed if isinstance(cert, asn1crypto.core.Any) else cert

                # The standard dictates it should be an OctetString, but we handle the Certificate sequence directly too
                if isinstance(inner, asn1crypto.core.OctetString):
                    cert_der = inner.native
                elif isinstance(inner, asn1crypto.x509.Certificate):
                    cert_der = inner.dump()
                else:
                    # ParsableOctetString (used by Oracle JDK): .contents gives the raw certificate DER
                    cert_der = inner.contents

                cert_pem = asn1crypto.pem.armor('CERTIFICATE', cert_der).decode('ascii').strip()
                certificates[tuple(cert_pem.splitlines())] = ()

        return certificates


class FetcherRootCertificateStoreOracleJDK(_FetcherRootCertificateStoreJDKBase):
    ORACLE_JDK_VERSION = 21
    ORACLE_JDK_DOWNLOAD_URL = (
        'https://download.oracle.com/java/{version}/latest/'
        'jdk-{version}_linux-x64_bin.tar.gz'
    )

    @classmethod
    def get_tarball_url(cls):
        return cls.ORACLE_JDK_DOWNLOAD_URL.format(version=cls.ORACLE_JDK_VERSION)

    @classmethod
    def _get_current_data(cls):
        data = HttpFetcher(connect_timeout=5, read_timeout=5)(cls.get_tarball_url())
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            for member in tar.getmembers():
                if member.name.endswith(cls._CACERTS_PATH_SUFFIX):
                    return tar.extractfile(member).read()

        raise NotImplementedError()


class FetcherRootCertificateStoreOpenJDK(_FetcherRootCertificateStoreJDKBase):
    OPENJDK_VERSION = 26
    _JDK_DOWNLOAD_PAGE_URL = 'https://jdk.java.net/{version}/'

    @classmethod
    def get_download_page_url(cls):
        return cls._JDK_DOWNLOAD_PAGE_URL.format(version=cls.OPENJDK_VERSION)

    @classmethod
    def _get_current_data(cls):
        fetcher = HttpFetcher(connect_timeout=5, read_timeout=5)
        page_data = fetcher(cls.get_download_page_url())
        soup = bs4.BeautifulSoup(page_data, 'html.parser')
        tarball_url = None
        for link in soup.find_all('a', href=True):
            if 'linux-x64_bin.tar.gz' in link['href']:
                tarball_url = link['href']
                break
        if tarball_url is None:
            raise NotImplementedError()
        data = fetcher(tarball_url)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            for member in tar.getmembers():
                if member.name.endswith(cls._CACERTS_PATH_SUFFIX):
                    return tar.extractfile(member).read()

        raise NotImplementedError()


class FetcherRootCertificateStore(FetcherBase):
    _ROOT_CERTIFICATE_STORE_UPDATERS = collections.OrderedDict([
        (Entity.MOZILLA, FetcherRootCertificateStoreMozilla),
        (Entity.GOOGLE, FetcherRootCertificateStoreChrome),
        (Entity.ANDROID, FetcherRootCertificateStoreAndroid),
        (Entity.MICROSOFT, FetcherRootCertificateStoreMicrosoft),
        (Entity.APPLE, FetcherRootCertificateStoreApple),
        (Entity.ORACLE, FetcherRootCertificateStoreOracleJDK),
        (Entity.OPENJDK, FetcherRootCertificateStoreOpenJDK),
    ])

    @classmethod
    def get_root_certificate_store_updaters(cls):
        return cls._ROOT_CERTIFICATE_STORE_UPDATERS

    @classmethod
    def _get_current_data(cls):
        return collections.OrderedDict([
            (store_owner, store_fetcher_class.from_current_data())
            for store_owner, store_fetcher_class in cls._ROOT_CERTIFICATE_STORE_UPDATERS.items()
        ])

    @classmethod
    def _transform_data(cls, current_data):
        root_certificates = {}

        for store_owner, root_store in current_data.items():
            for certificate_data, constraints in root_store.parsed_data.items():
                if certificate_data in root_certificates:
                    merged_constraints = root_certificates[certificate_data]
                else:
                    merged_constraints = []
                    root_certificates[certificate_data] = merged_constraints

                merged_constraints.append(RootCertificateTrustStoreConstraint(store_owner, constraints))

        merged_root_certificates = [
            RootCertificateParams(
                certificate=root_certificate.certificate,
                trust_stores=tuple(sorted(
                    root_certificate.trust_stores,
                    key=lambda trust_store: trust_store.owner.name,
                )),
            )
            for root_certificate in (
                RootCertificateParams(*item)
                for item in root_certificates.items()
            )
        ]

        return sorted(merged_root_certificates, key=lambda root_certificate: root_certificate.identifier)

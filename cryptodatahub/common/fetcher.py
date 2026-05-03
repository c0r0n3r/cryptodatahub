#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import base64
import collections
import csv
import datetime
import io
import json

import attr
import bs4
import urllib3

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.stores import (
    CertificateTransparencyLogParams,
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
class CertificatePemFetcher():
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
class FetcherBase():
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
class FetcherCertificateTransparencyLogs(FetcherBase):
    _CT_LOGS_ALL_JSON_URL = 'https://www.gstatic.com/ct/log_list/v3/all_logs_list.json'
    _CT_LOG_OPERATOR_NAME_GOOGLE_NAME = {
        'Up In The Air Consulting': 'Filippo Valsorda',
        'Wang Shengnan': 'GDCA',
    }

    @classmethod
    def _get_current_data(cls):
        http = urllib3.PoolManager()
        response = http.request('GET', cls._CT_LOGS_ALL_JSON_URL, preload_content=False)
        response.release_conn()

        return json.loads(response.data, object_pairs_hook=collections.OrderedDict)

    @classmethod
    def _transform_data(cls, current_data):
        transformed_logs = []

        for operator in current_data['operators']:
            logs = operator.pop('logs')
            for log in logs:
                if 'state' in log:
                    state = log.pop('state')
                    state_type = list(state)[0]
                    state_args = collections.OrderedDict([('state_type', state_type)])
                    state_args.update(state[state_type])
                    state_args.pop('final_tree_head', None)

                    log.update(collections.OrderedDict([('log_state', state_args)]))

                operator_name = operator['name']
                operator_name = cls._CT_LOG_OPERATOR_NAME_GOOGLE_NAME.get(operator_name, operator_name)
                log['operator'] = Entity[name_to_enum_item_name(operator_name)].name

                transformed_logs.append(CertificateTransparencyLogParams(**log))

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


class FetcherRootCertificateStoreGoogle(FetcherBase):
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


class FetcherRootCertificateStore(FetcherBase):
    _ROOT_CERTIFICATE_STORE_UPDATERS = collections.OrderedDict([
        (Entity.MOZILLA, FetcherRootCertificateStoreMozilla),
        (Entity.GOOGLE, FetcherRootCertificateStoreGoogle),
        (Entity.MICROSOFT, FetcherRootCertificateStoreMicrosoft),
        (Entity.APPLE, FetcherRootCertificateStoreApple),
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

        return [
            RootCertificateParams(*item)
            for item in root_certificates.items()
        ]

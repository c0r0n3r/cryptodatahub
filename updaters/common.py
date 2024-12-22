# -*- coding: utf-8 -*-

import abc
import collections
import csv
import io


import attr

from cryptodatahub.common.utils import HttpFetcher
from cryptodatahub.common.stores import RootCertificate


@attr.s(frozen=True)
class CertificatePemFetcher():
    http_fetcher = attr.ib(
        init=False,
        default=HttpFetcher(connect_timeout=5, read_timeout=30, retry=10),
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
    parsed_data = attr.ib(validator=attr.validators.instance_of(collections.abc.Iterable))

    @classmethod
    @abc.abstractmethod
    def _get_current_data(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _transform_data(cls, current_data):
        raise NotImplementedError()

    @classmethod
    def from_current_data(cls):
        current_data = cls._get_current_data()
        transformed_data = cls._transform_data(current_data)

        return cls(transformed_data)


@attr.s
class FetcherCsvBase(FetcherBase):
    @classmethod
    @abc.abstractmethod
    def _get_csv_url(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_csv_fields(cls):
        raise NotImplementedError()

    @classmethod
    def _get_fetcher(cls):
        return HttpFetcher()

    @classmethod
    def _get_current_data(cls):
        data = cls._get_fetcher()(cls._get_csv_url())

        csv_reader = csv.DictReader(
            io.StringIO(data.decode('utf-8')),
            fieldnames=cls._get_csv_fields(),
        )

        sample = data[:4096].decode('utf-8')
        if csv.Sniffer().has_header(sample):
            next(csv_reader, None)

        return csv_reader

    @classmethod
    @abc.abstractmethod
    def _transform_data(cls, current_data):
        raise NotImplementedError()


@attr.s
class UpdaterBase():
    fetcher_class = attr.ib(validator=attr.validators.instance_of(type))
    enum_class = attr.ib(validator=attr.validators.instance_of(type))
    enum_param_class = attr.ib(validator=attr.validators.instance_of(type))

    def _has_item_changed(self, enum_item_name, enum_item_value):
        try:
            return self.enum_class[enum_item_name].value != enum_item_value
        except KeyError:
            return True

    def _has_data_changed(self, current_data_items_by_name):
        return any(map(
            lambda item: self._has_item_changed(*item),
            current_data_items_by_name.items()
        ))

    def __call__(self):
        current_data = self.fetcher_class.from_current_data()
        current_data_items_by_name = {
            fetched_data_item.identifier: fetched_data_item
            for fetched_data_item in current_data.parsed_data
        }
        if self._has_data_changed(current_data_items_by_name):
            self.enum_class.set_json(self.enum_param_class, collections.OrderedDict([
                (identifier, current_data_items_by_name[identifier]._asdict())
                for identifier in sorted(current_data_items_by_name.keys())
            ]))

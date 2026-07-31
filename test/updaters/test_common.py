# SPDX-License-Identifier: MPL-2.0

import collections
import unittest

from test.common.classes import TEST_URL_PREFIX

import attr

from cryptodatahub.common.fetcher import FetcherBase, FetcherCsvBase
from cryptodatahub.common.utils import HttpFetcher, name_to_enum_item_name

from updaters.common import UpdaterBase


@attr.s
class FetcherBaseTest(FetcherBase):
    @classmethod
    def _get_current_data(cls):
        return b'data'

    @classmethod
    def _transform_data(cls, current_data):
        return {name_to_enum_item_name('data'): current_data.decode('ascii')}


class TestFetcherBase(unittest.TestCase):
    def test_current_data(self):
        self.assertEqual(FetcherBaseTest.from_current_data(), FetcherBaseTest({'DATA': 'data'}))


@attr.s
class FetcherCsvBaseTest(FetcherCsvBase):
    @classmethod
    def _get_csv_url(cls):
        return TEST_URL_PREFIX + 'test.csv'

    @classmethod
    def _get_fetcher(cls):
        return HttpFetcher()

    @classmethod
    def _transform_data(cls, current_data):
        return list(map(dict, current_data))


class TestFetcherCsvBase(unittest.TestCase):
    def test_current_data(self):
        self.assertEqual(
            FetcherCsvBaseTest.from_current_data(),
            FetcherCsvBaseTest([
                {'Col 1': 'Row 1, Col 1', 'Col 2': 'Row 1, Col 2'},
                {'Col 1': 'Row 2, Col 1', 'Col 2': 'Row 2, Col 2'},
            ])
        )


class UpdaterBaseTestItem:
    def __init__(self, identifier, value):
        self.identifier = identifier
        self._value = value

    def _asdict(self):
        return collections.OrderedDict(self._value)


class UpdaterBaseTestFetcher:
    parsed = []

    @classmethod
    def from_current_data(cls):
        return type('FetchedData', (), {'parsed_data': cls.parsed})()


class UpdaterBaseTestEnum:
    existing = []
    written = None

    @classmethod
    def get_json(cls, _param_class):
        return collections.OrderedDict((key, collections.OrderedDict(value)) for key, value in cls.existing)

    @classmethod
    def set_json(cls, _param_class, json_object):
        cls.written = json_object


class UpdaterBaseTest(UpdaterBase):
    def _has_data_changed(self, current_data_items_by_name):
        return True


class TestUpdaterBase(unittest.TestCase):
    def test_default_merge_updates_matching_keeps_removed_adds_new(self):
        UpdaterBaseTestEnum.existing = [
            ('KEPT', collections.OrderedDict([('value', 'old')])),
            ('REMOVED', collections.OrderedDict([('value', 'gone')])),
        ]
        UpdaterBaseTestFetcher.parsed = [
            UpdaterBaseTestItem('KEPT', collections.OrderedDict([('value', 'new')])),
            UpdaterBaseTestItem('ADDED', collections.OrderedDict([('value', 'fresh')])),
        ]

        UpdaterBaseTest(UpdaterBaseTestFetcher, UpdaterBaseTestEnum, object)()
        result = UpdaterBaseTestEnum.written

        # default _get_identity keys by the identifier; default _merge_existing replaces the value
        self.assertEqual(result['KEPT'], collections.OrderedDict([('value', 'new')]))
        self.assertEqual(result['REMOVED'], collections.OrderedDict([('value', 'gone')]))
        self.assertEqual(result['ADDED'], collections.OrderedDict([('value', 'fresh')]))

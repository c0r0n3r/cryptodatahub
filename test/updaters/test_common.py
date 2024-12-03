# -*- coding: utf-8 -*-

import unittest

from test.common.classes import TEST_URL_PREFIX

import attr

from cryptodatahub.common.utils import name_to_enum_item_name

from updaters.common import FetcherBase, FetcherCsvBase


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
    def _get_csv_fields(cls):
        return ['Col 1', 'Col 2']

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

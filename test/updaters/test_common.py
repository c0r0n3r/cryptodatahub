# -*- coding: utf-8 -*-

import urllib3

try:
    import unittest
    from unittest import mock
except ImportError:
    import unittest2 as unittest
    import mock

import attr

from cryptodatahub.common.utils import name_to_enum_item_name

from updaters.common import FetcherBase, FetcherCsvBase, HttpFetcher


TEST_URL_PREFIX = '/'.join([
    'https://gist.githubusercontent.com',
    'c0r0n3r',
    '54386701406df6e7299bd95c46a4c8d1',
    'raw',
    'e0b9cf606739d3fc1d97cc7f21e501e118bc4e07',
    ''
])


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


class TestHttpFetcher(unittest.TestCase):
    @mock.patch.object(urllib3.poolmanager.PoolManager, 'request', side_effect=NotImplementedError)
    def test_error_unhandaled_exception(self, _):
        with self.assertRaises(NotImplementedError):
            HttpFetcher()('http://example.com')

    def test_error_fetch_timeout(self):
        response = HttpFetcher(
            connect_timeout=0.001, read_timeout=0.001, retry=0
        )(
            TEST_URL_PREFIX + 'test.csv'
        )
        self.assertEqual(response, None)

    def test_fetch(self):
        data = HttpFetcher()(TEST_URL_PREFIX + 'test.html')
        self.assertEqual(data, b'\n'.join([
            b'<!DOCTYPE html>',
            b'<html>',
            b'  <body>',
            b'    Page content',
            b'  </body>',
            b'</html>',
        ]))

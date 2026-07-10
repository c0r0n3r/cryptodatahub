# SPDX-License-Identifier: MPL-2.0

from unittest import mock


class MockSelectedStoreFetcher:
    parsed_data = {}

    @classmethod
    def from_current_data(cls):
        return mock.Mock(parsed_data=cls.parsed_data)

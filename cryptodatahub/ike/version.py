# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import attr

from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataParamsEnumNumeric


@attr.s
class VersionParams(CryptoDataParamsEnumNumeric):
    code = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    def get_code_size(cls):
        return 1


IkeVersion = CryptoDataEnumBase('IkeVersion', CryptoDataEnumBase.get_json_records(VersionParams))

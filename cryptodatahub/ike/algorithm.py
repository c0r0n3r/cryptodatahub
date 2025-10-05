# -*- coding: utf-8 -*-

import attr

from cryptodatahub.common.types import CryptoDataEnumBase, CryptoDataEnumCodedBase, CryptoDataParamsEnumNumeric


@attr.s
class IkePayloadTypeParams(CryptoDataParamsEnumNumeric):
    """ISAKMP payload type parameters."""

    description = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def get_code_size(cls):
        return 1


IkePayloadType = CryptoDataEnumCodedBase(
    'PayloadType',
    CryptoDataEnumBase.get_json_records(IkePayloadTypeParams)
)

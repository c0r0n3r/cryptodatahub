# -*- coding: utf-8 -*-

import datetime
import enum
import six

import attr

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import (
    Base64Data,
    CryptoDataEnumBase,
    CryptoDataParamsBase,
    convert_base64_data,
    convert_datetime,
    convert_dict_to_object,
    convert_enum,
)


@attr.s(frozen=True)
class CertificateTransparencyOperator(CryptoDataParamsBase):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    email = attr.ib(
        default=(),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(six.string_types))
    )


CertificateTransparencyLogType = enum.Enum('CertificateTransparencyLogType', 'TEST PROD')
CertificateTransparencyLogStateType = enum.Enum(
    'CertificateTransparencyLogStateType', 'PENDING QUALIFIED USABLE READONLY RETIRED REJECTED'
)


@attr.s
class CertificateTransparencyLogState(CryptoDataParamsBase):
    state_type = attr.ib(
        converter=convert_enum(CertificateTransparencyLogStateType),
        validator=attr.validators.optional(attr.validators.instance_of(CertificateTransparencyLogStateType))
    )
    timestamp = attr.ib(
        converter=convert_datetime(),
        validator=attr.validators.instance_of(datetime.datetime),
    )


@attr.s
class CertificateTransparencyLogTemporalInterval(CryptoDataParamsBase):
    start_inclusive = attr.ib(
        converter=convert_datetime(),
        validator=attr.validators.instance_of(datetime.datetime),
    )
    end_exclusive = attr.ib(
        converter=convert_datetime(),
        validator=attr.validators.instance_of(datetime.datetime),
    )


@attr.s
class CertificateTransparencyLogParamsBase(CryptoDataParamsBase):
    log_id = attr.ib(
        converter=convert_base64_data(),
        validator=attr.validators.instance_of(Base64Data),
        metadata={'human_readable_name': 'ID'},
    )


class CertificateTransparencyLogUnknown(CertificateTransparencyLogParamsBase):
    pass


@attr.s(frozen=True)
class CertificateTransparencyLogParams(  # pylint: disable=too-many-instance-attributes
        CertificateTransparencyLogParamsBase
):
    operator = attr.ib(
        converter=convert_enum(Entity),
        validator=attr.validators.instance_of(Entity),
        metadata={'human_friendly': False},
    )
    key = attr.ib(
        converter=convert_base64_data(),
        validator=attr.validators.instance_of(Base64Data),
        metadata={'human_friendly': False},
    )
    url = attr.ib(
        validator=attr.validators.instance_of(six.string_types),
        metadata={'human_readable_name': 'URL', 'human_friendly': False},
    )
    mmd = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'Maximum Merge Delay', 'human_friendly': False},
    )
    description = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
    )
    dns = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        metadata={'human_friendly': False},
    )
    temporal_interval = attr.ib(
        default=None,
        converter=convert_dict_to_object(CertificateTransparencyLogTemporalInterval),
        validator=attr.validators.optional(attr.validators.instance_of(CertificateTransparencyLogTemporalInterval)),
        metadata={'human_readable_name': 'DNS', 'human_friendly': False},
    )
    log_type = attr.ib(
        default=None,
        converter=convert_enum(CertificateTransparencyLogType),
        validator=attr.validators.optional(attr.validators.instance_of(CertificateTransparencyLogType)),
        metadata={'human_friendly': False},
    )
    log_state = attr.ib(
        default=None,
        converter=convert_dict_to_object(CertificateTransparencyLogState),
        validator=attr.validators.optional(attr.validators.instance_of(CertificateTransparencyLogState))
    )

    def __attrs_post_init__(self):
        if self.mmd < 1:
            raise ValueError(self.mmd)


class CertificateTransparencyLogBase(CryptoDataEnumBase):
    @classmethod
    def from_log_id(cls, log_id):
        log_id = convert_base64_data()(log_id)
        try:
            log = cls._from_attr('log_id', log_id).value
        except InvalidValue:
            log = CertificateTransparencyLogUnknown(log_id)

        return log


CertificateTransparencyLog = CertificateTransparencyLogBase(
    'CertificateTransparencyLog', CryptoDataEnumBase.get_json_records(CertificateTransparencyLogParams)
)

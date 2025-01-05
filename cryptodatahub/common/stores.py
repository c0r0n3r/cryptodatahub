# -*- coding: utf-8 -*-

import collections
import datetime
import enum
import re

import attr

from cryptodatahub.common.algorithm import Hash
from cryptodatahub.common.entity import Entity, EntityRole
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.key import PublicKeyX509Base
from cryptodatahub.common.types import (
    Base64Data,
    CryptoDataEnumBase,
    CryptoDataParamsBase,
    CryptoDataParamsFetchedBase,
    convert_base64_data,
    convert_datetime,
    convert_dict_to_object,
    convert_enum,
    convert_iterable,
)
from cryptodatahub.common.utils import bytes_to_hex_string, name_to_enum_item_name


@attr.s(frozen=True)
class CertificateTransparencyOperator(CryptoDataParamsBase):
    name = attr.ib(validator=attr.validators.instance_of(str))
    email = attr.ib(
        default=(),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(str))
    )


CertificateTransparencyLogType = enum.Enum('CertificateTransparencyLogType', 'TEST PROD')
CertificateTransparencyLogStateType = enum.Enum(
    'CertificateTransparencyLogStateType', 'PENDING QUALIFIED USABLE READONLY RETIRED REJECTED'
)


class CertificateTransparencyLogDateTimeBase(CryptoDataParamsBase):
    @classmethod
    def _asdict_serializer(cls, _, __, value):
        if isinstance(value, datetime.datetime):
            return value.strftime("%Y-%m-%dT%H:%M:%SZ")

        return super()._asdict_serializer(_, __, value)


@attr.s(frozen=True)
class CertificateTransparencyLogState(CertificateTransparencyLogDateTimeBase):
    state_type = attr.ib(
        converter=convert_enum(CertificateTransparencyLogStateType),
        validator=attr.validators.optional(attr.validators.instance_of(CertificateTransparencyLogStateType))
    )
    timestamp = attr.ib(
        converter=convert_datetime(),
        validator=attr.validators.instance_of(datetime.datetime),
    )


@attr.s(frozen=True)
class CertificateTransparencyLogTemporalInterval(CertificateTransparencyLogDateTimeBase):
    start_inclusive = attr.ib(
        converter=convert_datetime(),
        validator=attr.validators.instance_of(datetime.datetime),
    )
    end_exclusive = attr.ib(
        converter=convert_datetime(),
        validator=attr.validators.instance_of(datetime.datetime),
    )


@attr.s(frozen=True)
class CertificateTransparencyLogParamsBase(CryptoDataParamsBase):
    log_id = attr.ib(
        converter=convert_base64_data(),
        validator=attr.validators.instance_of(Base64Data),
        metadata={'human_readable_name': 'ID'},
    )


class CertificateTransparencyLogUnknown(CertificateTransparencyLogParamsBase):
    def __str__(self):
        return str(self.log_id)


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
        validator=attr.validators.instance_of(str),
        metadata={'human_readable_name': 'URL', 'human_friendly': False},
    )
    mmd = attr.ib(
        validator=attr.validators.and_(attr.validators.instance_of(int), attr.validators.ge(1)),
        metadata={'human_readable_name': 'Maximum Merge Delay', 'human_friendly': False},
    )
    description = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(str)),
    )
    dns = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(str)),
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

    def __str__(self):
        return f'{self.description} ({self.log_id})'

    @classmethod
    def description_to_enum_item_name(cls, description):
        name = name_to_enum_item_name(description)

        name = re.sub('([^_])(20[12][0-9][_0-9]*)(H[1-2])?(_LOG)?$', '\\1_\\2\\3\\4', name)

        return name

    @property
    def identifier(self):
        return self.description_to_enum_item_name(self.description)


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


RootCertificateTrustConstraintAction = enum.Enum('RootCertificateTrustConstraintAction', 'DISTRUST DISTURB')


@attr.s(frozen=True)
class CertificateTrustConstraint():
    action = attr.ib(
        converter=convert_enum(RootCertificateTrustConstraintAction),
        validator=attr.validators.instance_of(RootCertificateTrustConstraintAction),
    )
    domains = attr.ib(
        default=(),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(str))
    )
    date = attr.ib(
        default=None,
        converter=convert_datetime('%Y-%m-%dT%H:%M:%S'),
        validator=attr.validators.optional(attr.validators.instance_of(datetime.datetime))
    )


@attr.s(repr=False, slots=True, hash=True)
class _RootCertificateParamCertificateConverter():
    def __call__(self, value):
        if value is None:
            return None

        if isinstance(value, PublicKeyX509Base):
            return value

        if not isinstance(value, (list, tuple)):
            return value

        try:
            return PublicKeyX509Base.from_pem_lines(value)
        except ValueError:
            pass

        return value

    def __repr__(self):
        return '<root certificate parameter converter>'


def convert_root_certificate_params():
    return _RootCertificateParamCertificateConverter()


@attr.s(frozen=True)
class RootCertificateTrustStoreConstraint(CryptoDataParamsBase):
    owner = attr.ib(
        converter=convert_enum(Entity),
        validator=attr.validators.instance_of(Entity)
    )
    constraints = attr.ib(
        default=(),
        converter=convert_iterable(convert_dict_to_object(CertificateTrustConstraint)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(CertificateTrustConstraint))
    )


@attr.s(frozen=True)
class RootCertificateParams(CryptoDataParamsFetchedBase):
    certificate = attr.ib(
        converter=convert_root_certificate_params(),
        validator=attr.validators.instance_of(PublicKeyX509Base)
    )
    trust_stores = attr.ib(
        default=(),
        converter=convert_iterable(convert_dict_to_object(RootCertificateTrustStoreConstraint)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(RootCertificateTrustStoreConstraint))
    )

    @classmethod
    def subject_to_enum_item_name(cls, subject, serial_number):
        if 'common_name' in subject:
            name = subject['common_name']
        elif 'organizational_unit_name' in subject:
            name = subject['organizational_unit_name']
        else:
            name = subject['organization_name']

        if not isinstance(name, str):
            name = ' '.join(name)

        return f'{name_to_enum_item_name(name)}_{serial_number}'

    @property
    def identifier(self):
        return self.subject_to_enum_item_name(self.certificate.subject, self.certificate.serial_number)

    def _asdict(self):
        dict_value = super()._asdict()
        dict_value['certificate'] = self.certificate.pem.splitlines()
        meta = collections.OrderedDict([
            ('_subject', self.certificate.subject),
            ('_fingerprints', collections.OrderedDict([
                (hash_algorithm.name, fingerprint)
                for hash_algorithm, fingerprint in self.certificate.fingerprints.items()
            ])),
        ])

        return collections.OrderedDict([('_meta', meta)] + list(dict_value.items()))

    def get_constraints_by_owner(self, owner):
        for trust_store_constraint in self.trust_stores:
            if trust_store_constraint.owner == owner:
                return trust_store_constraint.constraints

        raise KeyError(owner)


class RootCertificateBase(CryptoDataEnumBase):
    @classmethod
    def get_json_encoding(cls):
        return 'utf-8'

    @classmethod
    def get_item_by_sha2_256_fingerprint(cls, fingerprint_value):
        if not hasattr(cls, '_ITEMS_BY_SHA2_256_HASH'):
            cls._ITEMS_BY_SHA2_256_HASH = {
                bytes_to_hex_string(item.value.certificate.get_digest(Hash.SHA2_256)): item
                for item in cls
            }

        return cls._ITEMS_BY_SHA2_256_HASH[fingerprint_value.upper().replace(':', '')]

    @classmethod
    def get_items_by_trust_owner(cls, trust_owner):
        if not hasattr(cls, '_ITEMS_BY_TRUST_OWNER'):
            cls._ITEMS_BY_TRUST_OWNER = {
                _trust_owner: []
                for _trust_owner in Entity.get_items_by_role(EntityRole.CA_TRUST_STORE_OWNER)
            }

            for root_certificate in cls:
                for _trust_owner in map(lambda trust_store: trust_store.owner, root_certificate.value.trust_stores):
                    cls._ITEMS_BY_TRUST_OWNER[_trust_owner].append(root_certificate)

            cls._ITEMS_BY_TRUST_OWNER = cls._ITEMS_BY_TRUST_OWNER

        return cls._ITEMS_BY_TRUST_OWNER[trust_owner]


RootCertificate = RootCertificateBase(
    'RootCertificate', RootCertificateBase.get_json_records(RootCertificateParams)
)

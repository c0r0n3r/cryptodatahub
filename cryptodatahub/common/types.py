# -*- coding: utf-8 -*-

import codecs
import collections
import enum
import json
import inspect
import re

import six
from six.moves import collections_abc

try:
    import pathlib
except ImportError:  # pragma: no cover
    import pathlib2 as pathlib  # pragma: no cover

import attr

from cryptodatahub.common.exception import InvalidValue


@attr.s(repr=False, slots=True, hash=True)
class _DictObjectConverter(object):
    object_type = attr.ib(validator=attr.validators.instance_of(type))

    def __call__(self, value):
        if value is None:
            return None
        try:
            return self.object_type(**value)
        except TypeError:
            pass

        return value

    def __repr__(self):
        return '<dict to object converter>'


def convert_dict_to_object(object_type):
    return _DictObjectConverter(object_type)


@attr.s(repr=False, slots=True, hash=True)
class _EnumConverter(object):
    enum_type = attr.ib(validator=attr.validators.instance_of(type))

    def __call__(self, value):
        if value is None:
            return None

        if not isinstance(value, six.string_types):
            return value

        try:
            value = getattr(self.enum_type, value)
        except AttributeError:
            pass

        return value

    def __repr__(self):
        return '<enum converter>'


def convert_enum(enum_type):
    return _EnumConverter(enum_type)


@attr.s(repr=False, slots=True, hash=True)
class _IterableConverter(object):
    member_converter = attr.ib(validator=attr.validators.instance_of(collections_abc.Callable))

    def __call__(self, iterable):
        if iterable is None:
            return None

        try:
            for idx, member in enumerate(iterable):
                iterable[idx] = self.member_converter(member)
        except (TypeError, ValueError):
            pass

        return iterable

    def __repr__(self):
        return '<iterable converter>'


def convert_iterable(member_converter):
    return _IterableConverter(member_converter)


@attr.s(repr=False, slots=True, hash=True)
class _MappingConverter(object):
    key_converter = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(collections_abc.Callable)))
    value_converter = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(collections_abc.Callable)))

    def __call__(self, mapping):
        if mapping is None:
            return None

        if not isinstance(mapping, collections_abc.Mapping):
            return mapping

        try:
            key_value_pairs = [[key, value] for key, value in mapping.items()]
            if self.key_converter is not None:
                for pair in key_value_pairs:
                    pair[0] = self.key_converter(pair[0])
            if self.value_converter is not None:
                for pair in key_value_pairs:
                    pair[1] = self.value_converter(pair[1])
            mapping = type(mapping)(key_value_pairs)
        except (TypeError, ValueError):
            pass

        return mapping

    def __repr__(self):
        return '<mapping converter>'


def convert_mapping(key_converter=None, value_converter=None):
    return _MappingConverter(key_converter, value_converter)


@attr.s(frozen=True)
class ClientVersion(object):
    parts = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(int)))

    @classmethod
    def from_str(cls, version_str):
        try:
            return cls((int(version_str), ))
        except ValueError:
            pass

        return cls(tuple(map(int, version_str.split('.'))))

    def __str__(self):
        return '.'.join(map(str, self.parts))


@attr.s(repr=False, slots=True, hash=True)
class _ClientVersionConverter(object):
    def __call__(self, version):
        if version is None:
            return None

        if not isinstance(version, six.string_types):
            return version

        try:
            version = ClientVersion.from_str(version)
        except (TypeError, ValueError):
            pass

        return version

    def __repr__(self):
        return '<client version converter>'


def convert_client_version():
    return _ClientVersionConverter()


class CryptoDataParamsBase(object):
    pass


@attr.s(frozen=True)
class CryptoDataParamsNamed(CryptoDataParamsBase):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    long_name = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    def __str__(self):
        return self.name


@attr.s(frozen=True)
class CryptoDataParamsEnumNumeric(CryptoDataParamsBase):
    code = attr.ib()

    @code.validator
    def _validator_code(self, _, value):
        if not isinstance(value, int):
            raise ValueError(value)
        if value < 0:
            raise ValueError(value)
        if value >= 2 ** (self.get_code_size() * 8):
            raise ValueError(value)

    @classmethod
    def get_code_size(cls):
        raise NotImplementedError()


@attr.s(frozen=True)
class CryptoDataParamsEnumString(CryptoDataParamsBase):
    code = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def __str__(self):
        return self.code

    def _asdict(self):
        return str(self)

    def get_code_size(self):
        return len(self.code)


@attr.s(frozen=True)
class CryptoDataParamsOIDOptional(CryptoDataParamsNamed):
    oid = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))


class CryptoDataEnumBase(enum.Enum):
    def __new__(cls, value):
        member = object.__new__(cls)
        member._value_ = value
        return member

    @staticmethod
    def get_json_records(param_class):
        json_path = CryptoDataEnumBase.get_json_path(param_class)
        with codecs.open(str(json_path), 'r', encoding='ascii') as json_file:
            return collections.OrderedDict([
                (name, param_class(**{
                    init_param_name.replace('-', '_'): value
                    for init_param_name, value in params.items()
                    if not init_param_name.startswith('_')
                }))
                for name, params in json.load(json_file, object_pairs_hook=collections.OrderedDict).items()
            ])

    @staticmethod
    def get_json_path(param_class):
        if not param_class.__name__.endswith('Params'):
            raise TypeError(param_class)

        enum_class_name = param_class.__name__[:-6]
        enum_class_name_parts = [
            name_part.lower()
            for name_part in re.split("([A-Z]+[^A-Z]*)", enum_class_name)
            if name_part
        ]

        return pathlib.Path(inspect.getfile(param_class)).parent / ('-'.join(enum_class_name_parts) + '.json')

    @classmethod
    def _from_attr(cls, attr_name, value):
        for item in cls:
            if getattr(item.value, attr_name) == value:
                return item

        raise InvalidValue(value, cls, attr_name)


class CryptoDataEnumCodedBase(CryptoDataEnumBase):
    @classmethod
    def from_code(cls, code):
        return cls._from_attr('code', code)


class CryptoDataEnumOIDBase(CryptoDataEnumCodedBase):
    @classmethod
    def from_oid(cls, oid):
        return cls._from_attr('oid', oid)

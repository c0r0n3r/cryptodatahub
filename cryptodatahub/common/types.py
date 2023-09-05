# -*- coding: utf-8 -*-

import abc
import base64
import codecs
import collections
import datetime
import enum
import json
import inspect
import os
import re
import unicodedata

import dateutil.parser
import six
from six.moves import collections_abc

try:
    import pathlib
except ImportError:  # pragma: no cover
    import pathlib2 as pathlib  # pragma: no cover

import attr
import urllib3

from cryptodatahub.common.exception import InvalidValue


class _ConverterBase(object):
    @abc.abstractmethod
    def __call__(self, value):
        raise NotImplementedError()

    @abc.abstractmethod
    def __repr__(self):
        raise NotImplementedError()


@attr.s(repr=False, slots=True, hash=True)
class _DictObjectConverter(_ConverterBase):
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
class _ValueToObjectConverter(_ConverterBase):
    object_type = attr.ib(validator=attr.validators.instance_of(type))
    value_converter = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(_ConverterBase)))

    def __call__(self, value):
        if value is None:
            return None

        if isinstance(value, self.object_type):
            return value

        if self.value_converter is not None:
            value = self.value_converter(value)

        return self.object_type(value)

    def __repr__(self):
        return '<value to object converter>'


def convert_value_to_object(object_type, value_converter=None):
    return _ValueToObjectConverter(object_type, value_converter)


@attr.s(repr=False, slots=True, hash=True)
class _EnumConverter(_ConverterBase):
    enum_type = attr.ib(validator=attr.validators.instance_of(type))

    def __call__(self, value):
        if value is None:
            return None

        if not isinstance(value, six.string_types):
            return value

        try:
            value = getattr(self.enum_type, value.upper())
        except AttributeError:
            pass

        return value

    def __repr__(self):
        return '<enum converter>'


def convert_enum(enum_type):
    return _EnumConverter(enum_type)


@attr.s(frozen=True)
class Base64Data(object):
    value = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    def _asdict(self):
        return str(self)

    def __str__(self):
        return base64.b64encode(self.value).decode('ascii')


@attr.s(repr=False, slots=True, hash=True)
class _DateTimeConverter(_ConverterBase):
    strptime_format = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(str)))

    def __call__(self, date_time):
        if date_time is None:
            return None

        if isinstance(date_time, datetime.datetime):
            return date_time

        try:
            if self.strptime_format is None:
                date_time = dateutil.parser.isoparse(date_time)
            else:
                date_time = datetime.datetime.strptime(date_time, self.strptime_format)
        except (TypeError, ValueError):
            pass

        return date_time

    def __repr__(self):
        return '<datetime converter>'


def convert_datetime(strptime_format=None):
    return _DateTimeConverter(strptime_format)


@attr.s(repr=False, slots=True, hash=True)
class _Base64DataConverter(_ConverterBase):
    def __call__(self, value):
        if value is None:
            return None

        if isinstance(value, bytearray) or (six.PY3 and isinstance(value, bytes)):
            return Base64Data(value)

        if not isinstance(value, six.string_types):
            return value

        try:
            value = Base64Data(base64.b64decode(value))
        except (ValueError, TypeError):
            pass

        return value

    def __repr__(self):
        return '<base64 data converter>'


def convert_base64_data():
    return _Base64DataConverter()


@attr.s(repr=False, slots=True, hash=True)
class _BigNumberConverter(_ConverterBase):
    def __call__(self, value):
        if value is None:
            return None

        if not isinstance(value, collections_abc.Iterable):
            return value

        if not all(map(lambda big_number_part: isinstance(big_number_part, six.string_types), value)):
            return value

        try:
            value = int(''.join(value).replace('0x', '').replace(' ', '').replace(',', ''), 16)
        except ValueError:
            pass

        return value

    def __repr__(self):
        return '<big number converter>'


def convert_big_enum():
    return _BigNumberConverter()


@attr.s(repr=False, slots=True, hash=True)
class _IterableConverter(_ConverterBase):
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
class _MappingConverter(_ConverterBase):
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
class _ClientVersionConverter(_ConverterBase):
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


@attr.s(repr=False, slots=True, hash=True)
class _UrlConverter(_ConverterBase):
    def __call__(self, value):
        if value is None:
            return None

        if not isinstance(value, six.string_types):
            return value

        try:
            value = urllib3.util.parse_url(value)
        except urllib3.exceptions.LocationParseError:
            pass

        return value

    def __repr__(self):
        return '<url converter>'


def convert_url():
    return _UrlConverter()


@attr.s(repr=False, slots=True, hash=True)
class _VariadicConverter(_ConverterBase):
    converters = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(_ConverterBase))
    )

    def __call__(self, convertable):
        if convertable is None:
            return None

        for converter in self.converters:
            converted = converter(convertable)
            if id(converted) != id(convertable):
                return converted

        return convertable

    def __repr__(self):
        return '<variadic converter>'


def convert_variadic(converters):
    return _VariadicConverter(converters)


class CryptoDataParamsBase(object):
    @classmethod
    def get_init_attribute_names(cls):
        return [
            six.ensure_text(name)
            for name, attribute in attr.fields_dict(cls).items()
            if attribute.init
        ]

    def _asdict_filter(self, attribute, _):
        return not attribute.name.startswith('_')

    def _asdict_serializer(self, _, __, value):
        if hasattr(value, '_asdict'):
            return getattr(value, '_asdict')()
        if isinstance(value, enum.Enum):
            return value.name
        if isinstance(value, datetime.datetime):
            return str(value)

        return value

    def _asdict(self):
        return attr.asdict(
            self,
            filter=self._asdict_filter,
            dict_factory=collections.OrderedDict,
            value_serializer=self._asdict_serializer
        )


@attr.s(frozen=True)
class CryptoDataParamsFetchedBase(CryptoDataParamsBase):
    @property
    @abc.abstractmethod
    def identifier(self):
        raise NotImplementedError()


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
    @classmethod
    def get_json_records(cls, param_class):
        return collections.OrderedDict([
            (six.ensure_str(unicodedata.normalize('NFD', name).encode('ascii', 'ignore')), param_class(**{
                init_param_name.replace('-', '_'): value
                for init_param_name, value in params.items()
                if not init_param_name.startswith('_')
            }))
            for name, params in cls.get_json_object(param_class).items()
        ])

    @staticmethod
    def get_file_name_from_param_class(param_class):
        if not param_class.__name__.endswith('Params'):
            raise TypeError(param_class)

        enum_class_name = param_class.__name__[:-6]
        enum_class_name_parts = [
            name_part.lower()
            for name_part in re.split("([A-Z]+[^A-Z]*)", enum_class_name)
            if name_part
        ]

        return '-'.join(enum_class_name_parts) + '.json'

    @classmethod
    def get_json_path(cls, param_class):
        return (
            pathlib.Path(inspect.getfile(param_class)).parent /
            cls.get_file_name_from_param_class(param_class)
        )

    @classmethod
    def get_json_encoding(cls):
        return 'ascii'

    @classmethod
    def is_json_encoding_ascii(cls):
        return cls.get_json_encoding() == 'ascii'

    @classmethod
    def get_json_object(cls, param_class):
        json_path = cls.get_json_path(param_class)
        with codecs.open(str(json_path), 'r', encoding=cls.get_json_encoding()) as json_file:
            return json.load(json_file, object_pairs_hook=collections.OrderedDict)

    @classmethod
    def dump_json(cls, json_object):
        return json.dumps(json_object, ensure_ascii=cls.is_json_encoding_ascii(), indent=4) + os.linesep

    @classmethod
    def set_json(cls, param_class, json_object):
        json_path = cls.get_json_path(param_class)
        with codecs.open(str(json_path), 'w+', encoding=cls.get_json_encoding()) as json_file:
            json_file.write(cls.dump_json(json_object))

    @classmethod
    def get_json(cls, param_class):
        return cls.get_json_object(param_class)

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

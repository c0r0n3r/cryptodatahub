# -*- coding: utf-8 -*-

import binascii
import hashlib

import attr
import six
import urllib3

from cryptodatahub.common.algorithm import Hash


def bytes_to_hex_string(byte_array, separator='', lowercase=False):
    if lowercase:
        format_str = '{:02x}'
    else:
        format_str = '{:02X}'

    return separator.join([format_str.format(x) for x in six.iterbytes(bytes(byte_array))])


def bytes_from_hex_string(hex_string, separator=''):
    if separator:
        hex_string = ''.join(hex_string.split(separator))

    try:
        binary_data = binascii.a2b_hex(hex_string)
    except (TypeError, ValueError) as e:
        six.raise_from(ValueError(*e.args), e)

    return binary_data


def name_to_enum_item_name(name):
    converted_name = ''
    for char in name:
        if char.isalnum():
            converted_name += char
        elif converted_name and converted_name[-1] != '_':
            converted_name += '_'

    return converted_name.rstrip('_').upper()


_HASHLIB_FUNCS = {
    Hash.MD5: hashlib.md5,
    Hash.SHA1: hashlib.sha1,
    Hash.SHA2_224: hashlib.sha224,
    Hash.SHA2_256: hashlib.sha256,
    Hash.SHA2_384: hashlib.sha384,
    Hash.SHA2_512: hashlib.sha512,
}


def hash_bytes(hash_algorithm, hashable_value):
    try:
        hashlib_funcs = _HASHLIB_FUNCS[hash_algorithm]
    except KeyError as e:
        six.raise_from(NotImplementedError(hash_algorithm), e)

    return hashlib_funcs(hashable_value).digest()


@attr.s
class HttpFetcher(object):
    connect_timeout = attr.ib(default=2, validator=attr.validators.instance_of((int, float)))
    read_timeout = attr.ib(default=1, validator=attr.validators.instance_of((int, float)))
    retry = attr.ib(default=1, validator=attr.validators.instance_of(int))
    _request_params = attr.ib(default=None, init=False)
    _response = attr.ib(default=None, init=False)

    def __attrs_post_init__(self):
        request_params = {
            'preload_content': False,
            'timeout': urllib3.Timeout(connect=self.connect_timeout, read=self.read_timeout),
            'retries': urllib3.Retry(
                self.retry, status_forcelist=urllib3.Retry.RETRY_AFTER_STATUS_CODES | frozenset([502])
            ),
        }

        object.__setattr__(self, '_request_params', request_params)

    def get_response_header(self, header_name):
        if self._response is None:
            raise AttributeError()

        return self._response.headers.get(header_name, None)

    @property
    def response_data(self):
        if self._response is None:
            raise AttributeError()

        return self._response.data

    def fetch(self, url):
        pool_manager = urllib3.PoolManager()

        try:
            self._response = pool_manager.request('GET', str(url), **self._request_params)
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ != 'TimeoutError' and not isinstance(e, urllib3.exceptions.HTTPError):
                raise e

        pool_manager.clear()

    def __call__(self, url):
        self.fetch(url)

        return self.response_data

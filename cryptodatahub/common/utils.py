# -*- coding: utf-8 -*-

import binascii

import six


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

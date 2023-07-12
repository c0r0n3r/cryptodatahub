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


def name_to_enum_item_name(name):
    converted_name = ''
    for char in name:
        if char.isalnum():
            converted_name += char
        elif converted_name and converted_name[-1] != '_':
            converted_name += '_'

    return converted_name.rstrip('_').upper()

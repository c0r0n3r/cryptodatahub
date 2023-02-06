# -*- coding: utf-8 -*-

import enum
import six

import attr


@attr.s(init=False)
class InvalidValue(Exception):
    value = attr.ib()

    def __init__(self, value, type_class, class_member=None):
        if isinstance(value, enum.IntEnum):
            message = hex(value.value)
        elif isinstance(value, int):
            message = hex(value)
        else:
            message = value
        message = hex(value) if isinstance(value, int) else repr(value)
        type_name = type_class.__name__ if hasattr(type_class, '__name__') else str(type(type_class))
        message = six.ensure_text('{} is not a valid {}').format(message, type_name)
        if class_member is not None:
            message = six.ensure_text('{} {} value').format(message, class_member)

        super(InvalidValue, self).__init__(message)

        self.value = value

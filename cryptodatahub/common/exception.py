# SPDX-License-Identifier: MPL-2.0

import enum

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
        message = f'{message} is not a valid {type_name}'
        if class_member is not None:
            message = f'{message} {class_member} value'

        super().__init__(message)

        self.value = value


@attr.s
class InvalidProposalToken(Exception):
    token = attr.ib(validator=attr.validators.instance_of(str))
    hint = attr.ib(validator=attr.validators.instance_of(str))

    def __str__(self):
        return f'invalid proposal token; token="{self.token}", hint="{self.hint}"'

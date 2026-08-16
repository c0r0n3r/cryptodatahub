# SPDX-License-Identifier: MPL-2.0

import re

import attr

from cryptodatahub.common.utils import name_to_enum_item_name


@attr.s(frozen=True)
class OqsParameterSet:
    identifier = attr.ib(validator=attr.validators.instance_of(str))
    name = attr.ib(validator=attr.validators.instance_of(str))
    encapsulation_key_size = attr.ib(validator=attr.validators.instance_of(int))
    decapsulation_key_size = attr.ib(validator=attr.validators.instance_of(int))
    ciphertext_size = attr.ib(validator=attr.validators.instance_of(int))
    shared_secret_size = attr.ib(validator=attr.validators.instance_of(int))
    security_category = attr.ib(validator=attr.validators.instance_of(int))


SIZE_FIELDS = (
    'encapsulation_key_size', 'decapsulation_key_size', 'ciphertext_size', 'shared_secret_size',
)
_SIZE_FIELD_BY_DATASHEET_FIELD = {
    'encapsulation_key_size': 'length-public-key',
    'decapsulation_key_size': 'length-secret-key',
    'ciphertext_size': 'length-ciphertext',
    'shared_secret_size': 'length-shared-secret',
}
_MARKDOWN_COLUMNS_BY_FIELD = {
    'security_category': ('claimed nist security level', 'claimed nist level'),
    'encapsulation_key_size': ('public key size (bytes)',),
    'decapsulation_key_size': ('secret key size (bytes)',),
    'ciphertext_size': ('ciphertext size (bytes)',),
    'shared_secret_size': ('shared secret size (bytes)',),
}


def get_parameter_sets(datasheet):
    """The parameter sets of a machine readable datasheet, by their own name."""
    parameter_sets = {}
    for parameter_set in datasheet.get('parameter-sets', []):
        if 'claimed-nist-level' not in parameter_set:
            continue
        if any(field not in parameter_set for field in _SIZE_FIELD_BY_DATASHEET_FIELD.values()):
            continue

        parameter_sets[parameter_set['name']] = OqsParameterSet(
            identifier=name_to_enum_item_name(parameter_set['name']),
            name=parameter_set['name'],
            security_category=parameter_set['claimed-nist-level'],
            **{
                field: parameter_set[datasheet_field] * 8
                for field, datasheet_field in _SIZE_FIELD_BY_DATASHEET_FIELD.items()
            },
        )

    return parameter_sets


def get_nist_round(datasheet):
    nist_round = datasheet.get('nist-round')

    return nist_round if isinstance(nist_round, int) else None


def get_parameter_sets_of_markdown(markdown):
    """The same parameter sets out of the markdown form the earlier releases carry.

    Those releases state the numbers in a table instead of a machine readable
    file, and the table holds every value a record needs.
    """
    parameter_sets = {}
    header = None
    for line in markdown.splitlines():
        if '|' not in line:
            header = None
            continue

        cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
        if all(re.fullmatch(r':?-{2,}:?', cell) for cell in cells if cell):
            continue

        lowered = [cell.lower() for cell in cells]
        if 'parameter set' in lowered:
            header = lowered
            continue

        if header is None or len(cells) != len(header):
            continue

        parameter_set = _get_parameter_set_of_row(dict(zip(header, cells)))
        if parameter_set is not None:
            parameter_sets[parameter_set.name] = parameter_set

    return parameter_sets


def _get_parameter_set_of_row(row):
    name = row.get('parameter set', '').replace('*', '').strip()
    if not name:
        return None

    values = {}
    for field, columns in _MARKDOWN_COLUMNS_BY_FIELD.items():
        cell = next((row[column] for column in columns if column in row), None)
        if cell is None or not re.fullmatch(r'[\d ,]+', cell):
            return None

        value = int(cell.replace(',', '').replace(' ', ''))
        values[field] = value * 8 if field in SIZE_FIELDS else value

    return OqsParameterSet(identifier=name_to_enum_item_name(name), name=name, **values)


def get_nist_round_of_markdown(markdown):
    match = re.search(r'\*\*Version\*\*: NIST Round (\d)', markdown)

    return int(match.group(1)) if match else None

# SPDX-License-Identifier: MPL-2.0

import collections

import attr


@attr.s
class UpdaterBase:
    fetcher_class = attr.ib(validator=attr.validators.instance_of(type))
    enum_class = attr.ib(validator=attr.validators.instance_of(type))
    enum_param_class = attr.ib(validator=attr.validators.instance_of(type))

    def _has_item_changed(self, enum_item_name, enum_item_value):
        try:
            return self.enum_class[enum_item_name].value != enum_item_value
        except KeyError:
            return True

    def _has_data_changed(self, current_data_items_by_name):
        return any(map(
            lambda item: self._has_item_changed(*item),
            current_data_items_by_name.items()
        ))

    @classmethod
    def _merge(cls, existing_data, current_items_by_identifier):
        merged_data = collections.OrderedDict(existing_data)
        for identifier in sorted(current_items_by_identifier):
            merged_data[identifier] = current_items_by_identifier[identifier]._asdict()

        return merged_data

    def __call__(self):
        current_data = self.fetcher_class.from_current_data()
        current_items_by_identifier = collections.OrderedDict(
            (fetched_data_item.identifier, fetched_data_item)
            for fetched_data_item in current_data.parsed_data
        )
        if self._has_data_changed(current_items_by_identifier):
            existing_data = self.enum_class.get_json(self.enum_param_class)
            merged_data = self._merge(existing_data, current_items_by_identifier)
            self.enum_class.set_json(self.enum_param_class, merged_data)

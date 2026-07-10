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

    def _get_ordered_identifiers(self, current_data_items_by_name):
        existing_data = self.enum_class.get_json(self.enum_param_class)

        ordered_identifiers = [
            identifier
            for identifier in existing_data.keys()
            if identifier in current_data_items_by_name
        ]
        ordered_identifiers.extend(sorted(
            identifier
            for identifier in current_data_items_by_name.keys()
            if identifier not in existing_data
        ))

        return ordered_identifiers

    def __call__(self):
        current_data = self.fetcher_class.from_current_data()
        current_data_items_by_name = {
            fetched_data_item.identifier: fetched_data_item
            for fetched_data_item in current_data.parsed_data
        }
        if self._has_data_changed(current_data_items_by_name):
            self.enum_class.set_json(self.enum_param_class, collections.OrderedDict([
                (identifier, current_data_items_by_name[identifier]._asdict())
                for identifier in self._get_ordered_identifiers(current_data_items_by_name)
            ]))

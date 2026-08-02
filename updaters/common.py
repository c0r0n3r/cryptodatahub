# SPDX-License-Identifier: MPL-2.0

import collections

import attr


@attr.s
class UpdaterBase:
    fetcher_class = attr.ib(validator=attr.validators.instance_of(type))
    enum_class = attr.ib(validator=attr.validators.instance_of(type))
    enum_param_class = attr.ib(validator=attr.validators.instance_of(type))

    @staticmethod
    def sort_key(merged_item):
        identifier, _ = merged_item

        return identifier

    def _merge(self, existing_data, current_items_by_identifier):
        merged_data = collections.OrderedDict(existing_data)
        for identifier in sorted(current_items_by_identifier):
            merged_data[identifier] = current_items_by_identifier[identifier]._asdict()

        return collections.OrderedDict(sorted(merged_data.items(), key=self.sort_key))

    def __call__(self):
        current_data = self.fetcher_class.from_current_data()
        current_items_by_identifier = collections.OrderedDict(
            (fetched_data_item.identifier, fetched_data_item)
            for fetched_data_item in current_data.parsed_data
        )
        existing_data = self.enum_class.get_json(self.enum_param_class)
        merged_data = self._merge(existing_data, current_items_by_identifier)
        if merged_data != existing_data:
            self.enum_class.set_json(self.enum_param_class, merged_data)

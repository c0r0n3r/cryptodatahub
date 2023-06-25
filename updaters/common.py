# -*- coding: utf-8 -*-

import collections


class FetcherBase(object):
    def _get_current_data(self):
        raise NotImplementedError()

    def _transform_data(self, current_data):
        raise NotImplementedError()

    def _get_param_class(self):
        raise NotImplementedError()

    def get_current_data(self):
        current_data = self._get_current_data()
        transformed_data = self._transform_data(current_data)
        param_class_init_attribute_names = self._get_param_class().get_init_attribute_names()
        return collections.OrderedDict([
            (param_name, collections.OrderedDict([
                (attr_name, param_attrs[attr_name])
                for attr_name in param_class_init_attribute_names
                if attr_name in param_attrs
            ]))
            for param_name, param_attrs in sorted(transformed_data.items())
        ])


class UpdaterBase(FetcherBase):
    def _get_current_data(self):
        raise NotImplementedError()

    def _transform_data(self, current_data):
        raise NotImplementedError()

    def _get_enum_class(self):
        raise NotImplementedError()

    def _get_param_class(self):
        raise NotImplementedError()

    def _compare_data(self, current_data):
        return self._get_enum_class().get_json(self._get_param_class()) == current_data

    @staticmethod
    def convert_name(name):
        converted_name = ''
        for c in name:
            if c.isalnum():
                converted_name += c
            elif converted_name and converted_name[-1] != '_':
                converted_name += '_'

        return converted_name.rstrip('_').upper()

    def update(self):
        current_data = self.get_current_data()
        if not self._compare_data(current_data):
            self._get_enum_class().set_json(self._get_param_class(), current_data)

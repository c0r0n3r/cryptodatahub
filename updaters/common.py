# -*- coding: utf-8 -*-

import collections

from cryptodatahub.common.types import CryptoDataEnumBase


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

    def _get_param_class(self):
        raise NotImplementedError()

    def _compare_data(self, current_data):
        return CryptoDataEnumBase.get_json(self._get_param_class()) == current_data

    def update(self):
        current_data = self.get_current_data()
        if not self._compare_data(current_data):
            CryptoDataEnumBase.set_json(self._get_param_class(), current_data)

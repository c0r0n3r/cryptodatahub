# -*- coding: utf-8 -*-

try:
    import unittest
except ImportError:
    import unittest2 as unittest

import six

from updaters.common import UpdaterBase


class TestUpdaterBase(unittest.TestCase):
    def test_convert_name(self):
        self.assertEqual(UpdaterBase.convert_name('lower'), 'LOWER')
        self.assertEqual(UpdaterBase.convert_name('multiple part'), 'MULTIPLE_PART')
        self.assertEqual(UpdaterBase.convert_name('aplha 123'), 'APLHA_123')
        self.assertEqual(UpdaterBase.convert_name('m  u  l  t  i  s  p  a  c  e'), 'M_U_L_T_I_S_P_A_C_E')
        self.assertEqual(UpdaterBase.convert_name('trailing space  '), 'TRAILING_SPACE')
        self.assertEqual(UpdaterBase.convert_name(six.ensure_text('αβγ')), six.ensure_text('ΑΒΓ'))

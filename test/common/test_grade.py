# -*- coding: utf-8 -*-

import unittest

from test.common.classes import TestClasses, TestGradeableSimple

from cryptodatahub.common.grade import (
    AttackNamed,
    AttackType,
    Grade,
    Gradeable,
    GradeableComplex,
    GradeableVulnerabilities,
    Vulnerability,
)


class TestGradeable(unittest.TestCase):
    _VULNERABILITY_INTEGER_FACTORIZATION_INSECURE = Vulnerability(
        attack_type=AttackType.INTEGER_FACTORIZATION,
        grade=Grade.INSECURE,
        named=None
    )
    _VULNERABILITY_INTEGER_FACTORIZATION_WEAK = Vulnerability(
        attack_type=AttackType.INTEGER_FACTORIZATION,
        grade=Grade.WEAK,
        named=None
    )

    def test_min_grade(self):
        self.assertEqual(None, Gradeable.get_min_grade(None))
        self.assertEqual(None, Gradeable.get_min_grade([None]))
        self.assertEqual(None, Gradeable.get_min_grade([None, [None]]))

        self.assertEqual(Grade.SECURE, Gradeable.get_min_grade([]))
        self.assertEqual(Grade.SECURE, Gradeable.get_min_grade([[]]))

        self.assertEqual(TestGradeableSimple().grade, TestGradeableSimple().min_grade)
        self.assertEqual(TestGradeableSimple().grade.value.name, str(TestGradeableSimple()))

        gradeable_single = GradeableVulnerabilities([
            self._VULNERABILITY_INTEGER_FACTORIZATION_WEAK,
            self._VULNERABILITY_INTEGER_FACTORIZATION_INSECURE,
        ])
        self.assertEqual(Grade.INSECURE, gradeable_single.min_grade)
        self.assertEqual(Grade.INSECURE, Gradeable.get_min_grade([gradeable_single]))
        self.assertEqual(Grade.INSECURE, Gradeable.get_min_grade([
            self._VULNERABILITY_INTEGER_FACTORIZATION_WEAK,
            None,
            self._VULNERABILITY_INTEGER_FACTORIZATION_INSECURE,
        ]))

        gradeable_multiple = GradeableComplex()
        object.__setattr__(gradeable_multiple, 'gradeables', [
            self._VULNERABILITY_INTEGER_FACTORIZATION_WEAK,
            self._VULNERABILITY_INTEGER_FACTORIZATION_INSECURE,
        ])
        self.assertEqual(Grade.INSECURE, gradeable_multiple.min_grade)
        self.assertEqual(Grade.INSECURE, Gradeable.get_min_grade([gradeable_multiple]))
        self.assertEqual(Grade.INSECURE, Gradeable.get_min_grade([
            self._VULNERABILITY_INTEGER_FACTORIZATION_WEAK,
            None,
            self._VULNERABILITY_INTEGER_FACTORIZATION_INSECURE,
        ]))


class TestGradeTypeParams(unittest.TestCase):
    def test_eq(self):
        self.assertEqual(Grade.SECURE.value, Grade.SECURE.value)
        self.assertNotEqual(Grade.SECURE.value, Grade.INSECURE.value)

    def test_order(self):
        self.assertEqual(
            list(sorted(Grade, key=lambda grade: grade.value)),
            [Grade.INSECURE, Grade.WEAK, Grade.DEPRECATED, Grade.SECURE]
        )


class TestAttackNamed(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return AttackNamed


class TestAttackType(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return AttackType

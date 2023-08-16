# -*- coding: utf-8 -*-

import abc
import enum
import functools

import six

import attr

from cryptodatahub.common.types import (
    CryptoDataEnumBase,
    CryptoDataEnumOIDBase,
    CryptoDataParamsNamed,
    convert_enum,
    convert_iterable,
)


@functools.total_ordering
@attr.s(frozen=True, order=False, eq=False, hash=True)
class GradeTypeParams(CryptoDataParamsNamed):
    _numeric = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    def __eq__(self, other):
        return self._numeric == other._numeric

    def __lt__(self, other):
        return self._numeric < other._numeric


class Grade(enum.Enum):
    SECURE = GradeTypeParams(
        name="secure",
        long_name=None,
        numeric=0,
    )
    DEPRECATED = GradeTypeParams(
        name="deprecated",
        long_name=None,
        numeric=-1,
    )
    WEAK = GradeTypeParams(
        name="weak",
        long_name=None,
        numeric=-2,
    )
    INSECURE = GradeTypeParams(
        name="insecure",
        long_name=None,
        numeric=-3,
    )


@attr.s(frozen=True)
class VulnerabilityParams(CryptoDataParamsNamed):
    grade = attr.ib(converter=convert_enum(Grade), validator=attr.validators.instance_of(Grade))


Vulnerability = CryptoDataEnumOIDBase('Vulnerability', CryptoDataEnumBase.get_json_records(VulnerabilityParams))


@attr.s(frozen=True, eq=False)
class Gradeable(object):
    @staticmethod
    def _get_vulnerbilities(obj):
        if obj is None:
            return [None]

        if isinstance(obj, Vulnerability):
            return [obj]

        if isinstance(obj, (list, tuple)):
            result = []
            for gradeable in obj:
                if isinstance(gradeable, GradeableComplex):
                    result.append(Gradeable._get_vulnerbilities(gradeable.gradeables))
                elif isinstance(gradeable, GradeableVulnerabilities):
                    result.append(gradeable.vulnerabilities)
                else:
                    result.append(Gradeable._get_vulnerbilities(gradeable))

            return result

        raise NotImplementedError()

    @staticmethod
    def _flatten_vulnerabilities(vulnerabilities):
        if not vulnerabilities:
            return vulnerabilities

        if isinstance(vulnerabilities[0], list):
            return (
                Gradeable._flatten_vulnerabilities(vulnerabilities[0]) +
                Gradeable._flatten_vulnerabilities(vulnerabilities[1:])
            )
        return vulnerabilities[:1] + Gradeable._flatten_vulnerabilities(vulnerabilities[1:])

    @staticmethod
    def get_min_grade(vulnerabilities):
        vulnerabilities = Gradeable._flatten_vulnerabilities((Gradeable._get_vulnerbilities(vulnerabilities)))
        if not vulnerabilities:
            return Grade.SECURE

        grades = set(
            vulnerability.grade
            for vulnerability in vulnerabilities
            if vulnerability is not None
        )
        if grades:
            return min(grades, key=lambda grade: grade.value)

        return None

    @property
    @abc.abstractmethod
    def min_grade(self):
        raise NotImplementedError()


@attr.s(frozen=True, eq=False)
class GradeableVulnerabilities(Gradeable):
    vulnerabilities = attr.ib(
        converter=convert_iterable(convert_enum(Vulnerability)),
        validator=attr.validators.optional(
            validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(Vulnerability))
        )
    )

    @property
    def min_grade(self):
        return self.get_min_grade(self.vulnerabilities)


@attr.s(eq=False)
class GradeableComplex(Gradeable):
    gradeables = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.deep_iterable(
            member_validator=attr.validators.optional(attr.validators.instance_of(Gradeable))
        ))
    )

    @property
    def min_grade(self):
        return self.get_min_grade(self.gradeables)

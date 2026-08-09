# SPDX-License-Identifier: MPL-2.0

import math

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from test.common.classes import TestClasses

from cryptodatahub.common.algorithm import NamedGroup, NamedGroupType
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.grade import AttackNamed, Grade
from cryptodatahub.common.parameter import (
    DHParameterNumbers,
    DHParamWellKnown,
    ECParameterForm,
    ECParameterNumbersWeierstrassPrime,
    ECParamWellKnown,
    ECParamWellKnownParams,
    KeyEncapsulationMechanism,
)


class TestIsProbablePrime(unittest.TestCase):
    COMPOSITE_WITHOUT_SMALL_FACTOR = 41 * 43

    def test_prime(self):
        self.assertTrue(TestECParamWellKnown.is_probable_prime(2))
        self.assertTrue(TestECParamWellKnown.is_probable_prime(3))
        self.assertTrue(TestECParamWellKnown.is_probable_prime(65537))

    def test_composite(self):
        self.assertFalse(TestECParamWellKnown.is_probable_prime(1))
        self.assertFalse(TestECParamWellKnown.is_probable_prime(4))
        self.assertFalse(
            TestECParamWellKnown.is_probable_prime(self.COMPOSITE_WITHOUT_SMALL_FACTOR)
        )


class TestDHParamWellKnownParams(unittest.TestCase):
    def test_eq(self):
        self.assertEqual(DHParameterNumbers(1, 2), DHParameterNumbers(1, 2))
        self.assertEqual(DHParameterNumbers(1, 2, None), DHParameterNumbers(1, 2, None))

        self.assertNotEqual(DHParameterNumbers(1, 2, 3), DHParameterNumbers(1, 2, 4))
        self.assertEqual(DHParameterNumbers(1, 2, None), DHParameterNumbers(1, 2, 3))


class TestDHParamWellKnown(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return DHParamWellKnown

    def test_from_parameter_numbers(self):
        dh_param = DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP
        self.assertEqual(
            DHParamWellKnown.from_parameter_numbers(dh_param.value.parameter_numbers),
            dh_param
        )

    def test_str(self):
        self.assertEqual(
            str(DHParamWellKnown.RFC2539_768_BIT_MODP_GROUP.value),
            '768-bit MODP Group/Oakley Group 1 (RFC 2409, RFC 2539)'
        )
        self.assertEqual(
            str(DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024.value),
            '1024-bit Apache 2.0.18 builtin DH parameter'
        )

    def test_sources(self):
        sources = DHParamWellKnown.RFC2539_768_BIT_MODP_GROUP.value.sources
        self.assertEqual(
            [source.value.name for source in sources], ['RFC 2409', 'RFC 2539', 'IETF']
        )
        self.assertEqual(
            [
                source.value.name
                for source in DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024
                .value.sources
            ],
            ['Apache'],
        )

    def test_non_safe_prime(self):
        group = DHParamWellKnown.RFC5114_1024_BIT_MODP_GROUP_WITH_160_BIT_PRIME_ORDER_SUBGROUP
        self.assertIn(
            AttackNamed.NON_SAFE_PRIME,
            [vulnerability.named for vulnerability in group.value.vulnerabilities],
        )
        self.assertEqual(group.value.min_grade, Grade.DEPRECATED)

    def test_entries_of_one_name_stay_apart(self):
        self.assertEqual(
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_512.value.name,
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024.value.name,
        )
        self.assertNotEqual(
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_512,
            DHParamWellKnown.APPLICATION_SERVER_APACHE_VERSION_2_0_18_BIT_1024,
        )


class TestECParamWellKnownParams(unittest.TestCase):
    def test_error_parameter_form_mismatch(self):
        with self.assertRaisesRegex(
                InvalidValue, 'MONTGOMERY.* is not a valid ECParamWellKnownParams parameter_form value'
        ):
            ECParamWellKnownParams(
                name='prime field curve declared as a Montgomery curve',
                long_name=None,
                vulnerabilities=[],
                aliases=[],
                sources=[],
                parameter_form=ECParameterForm.MONTGOMERY,
                parameter_numbers=ECParameterNumbersWeierstrassPrime(
                    p=23, a=1, b=1, x=3, y=10, n=28, h=1, seed=None
                ),
            )


class TestECParamWellKnown(TestClasses.TestJsonBase):
    MILLER_RABIN_WITNESSES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    BINARY_PARAMETER_FORMS = (
        ECParameterForm.WEIERSTRASS_BINARY,
        ECParameterForm.WEIERSTRASS_BINARY_NORMAL_BASIS,
    )
    # The base point ANSI X9.62 publishes for this curve generates the whole group
    # rather than the prime order subgroup, and the file records what the standard
    # defines.
    CURVE_WITH_A_BASE_POINT_OUTSIDE_THE_PRIME_ORDER_SUBGROUP = 'c2onb239v5'

    @classmethod
    def _get_class(cls):
        return ECParamWellKnown

    @classmethod
    def _get_base_point_checks(cls):
        return {
            ECParameterForm.WEIERSTRASS_PRIME: cls._is_base_point_on_weierstrass_prime_curve,
            ECParameterForm.WEIERSTRASS_BINARY: cls._is_base_point_on_weierstrass_binary_curve,
            ECParameterForm.WEIERSTRASS_BINARY_NORMAL_BASIS:
                cls._is_base_point_on_weierstrass_binary_normal_basis_curve,
            ECParameterForm.MONTGOMERY: cls._is_base_point_on_montgomery_curve,
            ECParameterForm.TWISTED_EDWARDS: cls._is_base_point_on_twisted_edwards_curve,
        }

    @classmethod
    def _get_order_checks(cls):
        return {
            ECParameterForm.WEIERSTRASS_PRIME: cls._is_order_annihilating_on_weierstrass_prime_curve,
            ECParameterForm.WEIERSTRASS_BINARY: cls._is_order_annihilating_on_weierstrass_binary_curve,
            ECParameterForm.WEIERSTRASS_BINARY_NORMAL_BASIS:
                cls._is_order_annihilating_on_weierstrass_binary_normal_basis_curve,
            ECParameterForm.MONTGOMERY: cls._is_order_annihilating_on_montgomery_curve,
            ECParameterForm.TWISTED_EDWARDS: cls._is_order_annihilating_on_twisted_edwards_curve,
        }

    @staticmethod
    def is_probable_prime(candidate):
        if candidate < 2:
            return False

        for witness in TestECParamWellKnown.MILLER_RABIN_WITNESSES:
            if candidate % witness == 0:
                return candidate == witness

        odd_factor = candidate - 1
        power_of_two = 0
        while odd_factor % 2 == 0:
            odd_factor //= 2
            power_of_two += 1

        for witness in TestECParamWellKnown.MILLER_RABIN_WITNESSES:
            remainder = pow(witness, odd_factor, candidate)
            if remainder in (1, candidate - 1):
                continue

            for _ in range(power_of_two - 1):
                remainder = (remainder * remainder) % candidate
                if remainder == candidate - 1:
                    break
            else:
                return False

        return True

    @staticmethod
    def _multiply_in_binary_field(left, right, reduction_polynomial, degree):
        product = 0
        while right:
            if right & 1:
                product ^= left
            right >>= 1
            left <<= 1
            if left.bit_length() > degree:
                left ^= reduction_polynomial

        while product.bit_length() > degree:
            product ^= reduction_polynomial << (product.bit_length() - degree - 1)

        return product

    @staticmethod
    def _get_multiplicative_order(base, modulus):
        order = 1
        power = base % modulus
        while power != 1:
            power = power * base % modulus
            order += 1

        return order

    @staticmethod
    def _get_gaussian_normal_basis_pairs(degree, basis_type):
        modulus = basis_type * degree + 1
        order_element = 2
        while TestECParamWellKnown._get_multiplicative_order(order_element, modulus) != basis_type:
            order_element += 1

        positions = [0] * modulus
        element = 1
        for _ in range(basis_type):
            index = element
            for position in range(degree):
                positions[index] = position
                index = 2 * index % modulus
            element = order_element * element % modulus

        return [(positions[step + 1], positions[modulus - step]) for step in range(1, modulus - 1)]

    @staticmethod
    def _rotate_in_normal_basis(value, shift, degree):
        return ((value << shift) | (value >> (degree - shift))) & ((1 << degree) - 1)

    @staticmethod
    def _multiply_in_normal_basis(left, right, pairs, degree):
        product = 0
        for left_shift, right_shift in pairs:
            product ^= (
                TestECParamWellKnown._rotate_in_normal_basis(left, left_shift, degree) &
                TestECParamWellKnown._rotate_in_normal_basis(right, right_shift, degree)
            )

        return product

    @staticmethod
    def _get_reduction_polynomial(parameter_numbers):
        reduction_polynomial = (1 << parameter_numbers.m) | 1
        for exponent in (parameter_numbers.k1, parameter_numbers.k2, parameter_numbers.k3):
            if exponent:
                reduction_polynomial |= 1 << exponent

        return reduction_polynomial

    @staticmethod
    def _is_base_point_on_weierstrass_prime_curve(parameter_numbers):
        prime = parameter_numbers.p
        point_x = parameter_numbers.x
        left_hand_side = pow(parameter_numbers.y, 2, prime)
        right_hand_side = pow(point_x, 3, prime) + parameter_numbers.a * point_x + parameter_numbers.b

        return left_hand_side == right_hand_side % prime

    @staticmethod
    def _is_base_point_on_weierstrass_binary_curve(parameter_numbers):
        degree = parameter_numbers.m
        reduction_polynomial = TestECParamWellKnown._get_reduction_polynomial(parameter_numbers)

        def multiply(left, right):
            return TestECParamWellKnown._multiply_in_binary_field(left, right, reduction_polynomial, degree)

        point_x = parameter_numbers.x
        point_y = parameter_numbers.y
        square_x = multiply(point_x, point_x)
        left_hand_side = multiply(point_y, point_y) ^ multiply(point_x, point_y)
        right_hand_side = multiply(point_x, square_x) ^ multiply(parameter_numbers.a, square_x) ^ parameter_numbers.b

        return left_hand_side == right_hand_side

    @staticmethod
    def _is_base_point_on_weierstrass_binary_normal_basis_curve(parameter_numbers):
        degree = parameter_numbers.m
        pairs = TestECParamWellKnown._get_gaussian_normal_basis_pairs(
            degree, parameter_numbers.gaussian_normal_basis_type
        )

        def multiply(left, right):
            return TestECParamWellKnown._multiply_in_normal_basis(left, right, pairs, degree)

        point_x = parameter_numbers.x
        point_y = parameter_numbers.y
        square_x = multiply(point_x, point_x)
        left_hand_side = multiply(point_y, point_y) ^ multiply(point_x, point_y)
        right_hand_side = multiply(point_x, square_x) ^ multiply(parameter_numbers.a, square_x) ^ parameter_numbers.b

        return left_hand_side == right_hand_side

    @staticmethod
    def _is_base_point_on_montgomery_curve(parameter_numbers):
        prime = parameter_numbers.p
        point_u = parameter_numbers.u
        left_hand_side = parameter_numbers.b * pow(parameter_numbers.v, 2, prime)
        right_hand_side = pow(point_u, 3, prime) + parameter_numbers.a * pow(point_u, 2, prime) + point_u

        return left_hand_side % prime == right_hand_side % prime

    @staticmethod
    def _is_base_point_on_twisted_edwards_curve(parameter_numbers):
        prime = parameter_numbers.p
        square_x = pow(parameter_numbers.x, 2, prime)
        square_y = pow(parameter_numbers.y, 2, prime)
        left_hand_side = parameter_numbers.a * square_x + square_y
        right_hand_side = 1 + parameter_numbers.d * square_x * square_y

        return left_hand_side % prime == right_hand_side % prime

    @staticmethod
    def _is_order_annihilating_on_weierstrass_prime_curve(parameter_numbers):
        prime = parameter_numbers.p
        coefficient = parameter_numbers.a

        def add_points(first, second):
            if first is None:
                return second
            if second is None:
                return first

            first_x, first_y = first
            second_x, second_y = second

            if first_x == second_x:
                if (first_y + second_y) % prime == 0:
                    return None

                slope = (3 * first_x * first_x + coefficient) * pow(2 * first_y, -1, prime) % prime
            else:
                slope = (second_y - first_y) * pow(second_x - first_x, -1, prime) % prime

            result_x = (slope * slope - first_x - second_x) % prime
            result_y = (slope * (first_x - result_x) - first_y) % prime

            return (result_x, result_y)

        result = None
        addend = (parameter_numbers.x, parameter_numbers.y)
        scalar = parameter_numbers.n
        while scalar:
            if scalar & 1:
                result = add_points(result, addend)
            addend = add_points(addend, addend)
            scalar >>= 1

        return result is None

    @staticmethod
    def _is_order_annihilating_in_binary_field(parameter_numbers, multiply, square, one):
        base_point_x = parameter_numbers.x
        coefficient = parameter_numbers.b

        def add_points(first_x, first_z, second_x, second_z):
            first_cross = multiply(first_x, second_z)
            second_cross = multiply(second_x, first_z)
            result_z = square(first_cross ^ second_cross)

            return multiply(base_point_x, result_z) ^ multiply(first_cross, second_cross), result_z

        def double_point(coordinate_x, coordinate_z):
            return (
                square(square(coordinate_x)) ^ multiply(coefficient, square(square(coordinate_z))),
                square(multiply(coordinate_x, coordinate_z)),
            )

        first_x, first_z = base_point_x, one
        second_x, second_z = double_point(base_point_x, one)

        for bit_index in reversed(range(parameter_numbers.n.bit_length() - 1)):
            if parameter_numbers.n >> bit_index & 1:
                first_x, first_z = add_points(first_x, first_z, second_x, second_z)
                second_x, second_z = double_point(second_x, second_z)
            else:
                second_x, second_z = add_points(first_x, first_z, second_x, second_z)
                first_x, first_z = double_point(first_x, first_z)

        return first_z == 0

    @staticmethod
    def _is_order_annihilating_on_weierstrass_binary_curve(parameter_numbers):
        degree = parameter_numbers.m
        reduction_polynomial = TestECParamWellKnown._get_reduction_polynomial(parameter_numbers)

        def multiply(left, right):
            return TestECParamWellKnown._multiply_in_binary_field(left, right, reduction_polynomial, degree)

        return TestECParamWellKnown._is_order_annihilating_in_binary_field(
            parameter_numbers, multiply, lambda value: multiply(value, value), 1
        )

    @staticmethod
    def _add_points_on_montgomery_curve(doubled, summed, base_point_u, prime):
        doubled_u, doubled_w = doubled
        summed_u, summed_w = summed

        first_cross = (summed_u - summed_w) * (doubled_u + doubled_w) % prime
        second_cross = (summed_u + summed_w) * (doubled_u - doubled_w) % prime

        return (
            pow(first_cross + second_cross, 2, prime),
            base_point_u * pow(first_cross - second_cross, 2, prime) % prime,
        )

    @staticmethod
    def _double_point_on_montgomery_curve(point, coefficient, prime):
        coordinate_u, coordinate_w = point

        square_total = pow(coordinate_u + coordinate_w, 2, prime)
        square_difference = pow(coordinate_u - coordinate_w, 2, prime)
        excess = (square_total - square_difference) % prime

        return (
            square_total * square_difference % prime,
            excess * (square_difference + coefficient * excess) % prime,
        )

    @staticmethod
    def _is_order_annihilating_on_montgomery_curve(parameter_numbers):
        prime = parameter_numbers.p
        base_point_u = parameter_numbers.u
        coefficient = (parameter_numbers.a + 2) * pow(4, -1, prime) % prime

        doubled = (1, 0)
        summed = (base_point_u, 1)
        swapped = 0

        for bit_index in reversed(range(parameter_numbers.n.bit_length())):
            bit = parameter_numbers.n >> bit_index & 1
            if swapped ^ bit:
                doubled, summed = summed, doubled
            swapped = bit

            doubled, summed = (
                TestECParamWellKnown._double_point_on_montgomery_curve(doubled, coefficient, prime),
                TestECParamWellKnown._add_points_on_montgomery_curve(doubled, summed, base_point_u, prime),
            )

        if swapped:
            doubled = summed

        return doubled[1] % prime == 0

    @staticmethod
    def _is_order_annihilating_on_twisted_edwards_curve(parameter_numbers):
        prime = parameter_numbers.p
        coefficient = parameter_numbers.a
        twist = parameter_numbers.d

        def add_points(first, second):
            first_x, first_y = first
            second_x, second_y = second

            product = twist * first_x * second_x * first_y * second_y % prime
            result_x = (first_x * second_y + first_y * second_x) * pow(1 + product, -1, prime) % prime
            result_y = (first_y * second_y - coefficient * first_x * second_x) * pow(1 - product, -1, prime) % prime

            return (result_x, result_y)

        result = (0, 1)
        addend = (parameter_numbers.x, parameter_numbers.y)
        scalar = parameter_numbers.n
        while scalar:
            if scalar & 1:
                result = add_points(result, addend)
            addend = add_points(addend, addend)
            scalar >>= 1

        return result == (0, 1)

    @staticmethod
    def _is_order_annihilating_on_weierstrass_binary_normal_basis_curve(parameter_numbers):
        degree = parameter_numbers.m
        pairs = TestECParamWellKnown._get_gaussian_normal_basis_pairs(
            degree, parameter_numbers.gaussian_normal_basis_type
        )

        return TestECParamWellKnown._is_order_annihilating_in_binary_field(
            parameter_numbers,
            lambda left, right: TestECParamWellKnown._multiply_in_normal_basis(left, right, pairs, degree),
            lambda value: TestECParamWellKnown._rotate_in_normal_basis(value, degree - 1, degree),
            (1 << degree) - 1,
        )

    @staticmethod
    def _is_group_order_in_hasse_interval(ec_param_well_known_params):
        parameter_numbers = ec_param_well_known_params.parameter_numbers
        if ec_param_well_known_params.parameter_form in TestECParamWellKnown.BINARY_PARAMETER_FORMS:
            field_size = 1 << parameter_numbers.m
        else:
            field_size = parameter_numbers.p

        return abs(parameter_numbers.n * parameter_numbers.h - field_size - 1) <= 2 * math.isqrt(field_size)

    def test_from_named_group(self):
        self.assertEqual(
           ECParamWellKnown.from_named_group(NamedGroup.PRIME256V1),
           ECParamWellKnown.PRIME256V1
        )

        with self.assertRaisesRegex(
                InvalidValue, "NamedGroup.ML_KEM_768.* is not a valid ECParamWellKnown"
        ) as context_manager:
            ECParamWellKnown.from_named_group(NamedGroup.ML_KEM_768)
        self.assertEqual(context_manager.exception.value, NamedGroup.ML_KEM_768)

    def test_every_elliptic_curve_named_group_has_an_entry(self):
        self.assertEqual([
            named_group.name
            for named_group in NamedGroup
            if named_group.value.group_type == NamedGroupType.ELLIPTIC_CURVE and
            named_group.name not in ECParamWellKnown.__members__
        ], [])

    def test_from_parameter_numbers(self):
        ec_param = ECParamWellKnown.PRIME256V1
        self.assertEqual(
           ECParamWellKnown.from_parameter_numbers(ec_param.value.parameter_numbers),
           ec_param
        )

    def test_field_size_is_prime(self):
        self.assertEqual([
            ec_param.name
            for ec_param in ECParamWellKnown
            if ec_param.value.parameter_form not in self.BINARY_PARAMETER_FORMS and
            not self.is_probable_prime(ec_param.value.parameter_numbers.p)
        ], [])

    def test_reduction_polynomial_is_trinomial_or_pentanomial(self):
        self.assertEqual([
            ec_param.name
            for ec_param in ECParamWellKnown
            if ec_param.value.parameter_form == ECParameterForm.WEIERSTRASS_BINARY and
            bin(self._get_reduction_polynomial(ec_param.value.parameter_numbers)).count('1') not in (3, 5)
        ], [])

    def test_base_point_is_on_curve(self):
        self.assertEqual([
            ec_param.name
            for ec_param in ECParamWellKnown
            if not self._get_base_point_checks()[ec_param.value.parameter_form](ec_param.value.parameter_numbers)
        ], [])

    def test_order_annihilates_the_base_point(self):
        self.assertEqual([
            ec_param.value.name
            for ec_param in ECParamWellKnown
            if not self._get_order_checks()[ec_param.value.parameter_form](ec_param.value.parameter_numbers)
        ], [self.CURVE_WITH_A_BASE_POINT_OUTSIDE_THE_PRIME_ORDER_SUBGROUP])

    def test_group_order_is_in_hasse_interval(self):
        self.assertEqual([
            ec_param.name
            for ec_param in ECParamWellKnown
            if not self._is_group_order_in_hasse_interval(ec_param.value)
        ], [])


class TestKeyEncapsulationMechanism(TestClasses.TestJsonBase):
    @classmethod
    def _get_class(cls):
        return KeyEncapsulationMechanism

    def test_from_named_group(self):
        self.assertEqual(
            KeyEncapsulationMechanism.from_named_group(NamedGroup.ML_KEM_768),
            KeyEncapsulationMechanism.ML_KEM_768
        )

        with self.assertRaisesRegex(
                InvalidValue, "NamedGroup.PRIME256V1.* is not a valid KeyEncapsulationMechanism"
        ) as context_manager:
            KeyEncapsulationMechanism.from_named_group(NamedGroup.PRIME256V1)
        self.assertEqual(context_manager.exception.value, NamedGroup.PRIME256V1)

    def test_named_group_exists(self):
        self.assertEqual([
            key_encapsulation_mechanism.name
            for key_encapsulation_mechanism in KeyEncapsulationMechanism
            if key_encapsulation_mechanism.name not in NamedGroup.__members__
        ], [])

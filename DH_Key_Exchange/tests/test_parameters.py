import unittest
from Crypto.Util.number import isPrime
from parameters import (generate_prime, validate_received_modulus,
                        prime_factors, is_generator, find_generator)


class TestGeneratePrime(unittest.TestCase):

    def test_exact_bit_length_and_odd(self):
        for bits in (16, 24, 32):
            p = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertEqual(p % 2, 1)
            self.assertTrue(isPrime(p))

    def test_default_is_16(self):
        self.assertEqual(generate_prime().bit_length(), 16)

    def test_bad_sizes(self):
        for bits in (12, 33, 0, -5):
            with self.assertRaises(ValueError):
                generate_prime(bits)

    def test_bad_types(self):
        for bits in (True, 16.0, "16", None):
            with self.assertRaises(TypeError):
                generate_prime(bits)


class TestValidateModulus(unittest.TestCase):

    def test_composite_rejected(self):
        with self.assertRaises(ValueError):
            validate_received_modulus(32769)

    def test_good_prime_accepted(self):
        self.assertTrue(validate_received_modulus(generate_prime(16)))

    def test_wrong_types_rejected(self):
        for p in ("32769", 32769.0, None, True):
            with self.assertRaises(TypeError):
                validate_received_modulus(p)

    def test_wrong_size_rejected(self):
        with self.assertRaises(ValueError):
            validate_received_modulus(23)
        with self.assertRaises(ValueError):
            validate_received_modulus(2 ** 40 + 15)  # 41 bits

    def test_fixture_path(self):
        self.assertTrue(validate_received_modulus(23, allow_fixture=True))
        with self.assertRaises(ValueError):
            validate_received_modulus(21, allow_fixture=True)


class TestFactors(unittest.TestCase):

    def test_examples(self):
        self.assertEqual(prime_factors(1), set())
        self.assertEqual(prime_factors(22), {2, 11})
        self.assertEqual(prime_factors(65536), {2})
        self.assertEqual(prime_factors(23), {23})

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            prime_factors(0)
        with self.assertRaises(TypeError):
            prime_factors(2.0)


class TestGenerators(unittest.TestCase):

    def test_p23(self):
        self.assertTrue(is_generator(5, 23, {2, 11}))
        self.assertFalse(is_generator(2, 23, {2, 11}))

    def test_p65537(self):
        self.assertTrue(is_generator(3, 65537, {2}))

    def test_find_generator(self):
        self.assertEqual(find_generator(23), 5)
        self.assertEqual(find_generator(65537), 3)

    def test_out_of_range_g(self):
        with self.assertRaises(ValueError):
            is_generator(28, 23, {2, 11})

    def test_composite_p(self):
        with self.assertRaises(ValueError):
            find_generator(21)


if __name__ == "__main__":
    unittest.main()

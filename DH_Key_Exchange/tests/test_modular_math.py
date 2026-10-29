import unittest
from modular_math import modular_exponentiation


class TestModularMath(unittest.TestCase):

    def test_known_result(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_exponent_zero(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)

    def test_modulus_one(self):
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 3, 23), pow(-5, 3, 23))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, 0)
        with self.assertRaises(TypeError):
            modular_exponentiation(5.5, 6, 23)
        with self.assertRaises(TypeError):
            modular_exponentiation(True, 6, 23)

    def test_compare_with_pow(self):
        # pow is only used here to check our answer
        for base in range(0, 30):
            for exponent in range(0, 30):
                self.assertEqual(modular_exponentiation(base, exponent, 97),
                                 pow(base, exponent, 97))


if __name__ == "__main__":
    unittest.main()

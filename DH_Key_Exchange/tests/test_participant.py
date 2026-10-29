import unittest
from parameters import find_generator, generate_prime
from participant import (Participant, check_public_value, compute_shared_secret,
                         generate_key_pair, generate_private_exponent,
                         provision_trusted_keys)


class TestDiffieHellman(unittest.TestCase):

    def test_private_exponent_range(self):
        for i in range(500):
            a = generate_private_exponent(23)
            self.assertTrue(2 <= a <= 21)

    def test_public_value_check(self):
        check_public_value(8, 23)  # should not raise
        for value in (0, 1, 22, 23):
            with self.assertRaises(ValueError):
                check_public_value(value, 23)
        with self.assertRaises(TypeError):
            check_public_value("8", 23)

    def test_fixture(self):
        self.assertEqual(generate_key_pair(5, 23, 6), (6, 8))
        self.assertEqual(generate_key_pair(5, 23, 15), (15, 19))
        self.assertEqual(compute_shared_secret(19, 6, 23), 2)
        self.assertEqual(compute_shared_secret(8, 15, 23), 2)

    def test_generated_exchanges(self):
        for bits in (16, 24, 32):
            p = generate_prime(bits)
            g = find_generator(p)
            a, A = generate_key_pair(g, p)
            b, B = generate_key_pair(g, p)
            self.assertEqual(compute_shared_secret(B, a, p),
                             compute_shared_secret(A, b, p))


class TestParticipant(unittest.TestCase):

    def test_names(self):
        self.assertEqual(Participant("Alice").name, "Alice")
        with self.assertRaises(ValueError):
            Participant("Eve")

    def test_trusted_keys(self):
        alice = Participant("Alice")
        bob = Participant("Bob")
        self.assertEqual(alice.trusted_keys, {})
        provision_trusted_keys(alice, bob)
        self.assertIs(alice.trusted_keys["Bob"], bob.verification_key)
        self.assertIs(bob.trusted_keys["Alice"], alice.verification_key)


if __name__ == "__main__":
    unittest.main()

import unittest
from authentication import ProtocolError
from parameters import find_generator, generate_prime
from participant import Participant, provision_trusted_keys
from protocol import AliceSide, BobSide


def make_sides():
    alice = Participant("Alice")
    bob = Participant("Bob")
    provision_trusted_keys(alice, bob)
    return AliceSide(alice), BobSide(bob)


class TestExchange(unittest.TestCase):

    def test_fixture_exchange(self):
        alice, bob = make_sides()
        message1 = alice.start_exchange(23, 5, private_exponent=6)
        message2 = bob.handle_init(*message1, allow_fixture=True,
                                   private_exponent=15)
        message3 = alice.handle_response(*message2)
        bob_session = bob.handle_finish(*message3)
        self.assertEqual(alice.last_session.public, 8)
        self.assertEqual(bob_session.public, 19)
        self.assertEqual(alice.last_session.secret, 2)
        self.assertEqual(bob_session.secret, 2)

    def test_fixture_needs_the_flag(self):
        alice, bob = make_sides()
        message1 = alice.start_exchange(23, 5, private_exponent=6)
        with self.assertRaises(ProtocolError):
            bob.handle_init(*message1)

    def test_generated_exchanges(self):
        alice, bob = make_sides()
        for bits in (16, 24, 32):
            for i in range(3):
                p = generate_prime(bits)
                g = find_generator(p)
                message1 = alice.start_exchange(p, g)
                message2 = bob.handle_init(*message1)
                message3 = alice.handle_response(*message2)
                bob_session = bob.handle_finish(*message3)
                self.assertEqual(alice.last_session.secret, bob_session.secret)


class TestParameterChecks(unittest.TestCase):

    def test_composite_modulus(self):
        alice, bob = make_sides()
        message1 = alice.start_exchange(32769, 3, private_exponent=5)
        with self.assertRaises(ProtocolError):
            bob.handle_init(*message1)

    def test_bad_generator(self):
        # 2 is not a generator for p = 23
        alice, bob = make_sides()
        message1 = alice.start_exchange(23, 2, private_exponent=3)
        with self.assertRaises(ProtocolError):
            bob.handle_init(*message1, allow_fixture=True)


class TestSessionState(unittest.TestCase):

    def setUp(self):
        self.alice, self.bob = make_sides()
        self.p = generate_prime(16)
        self.g = find_generator(self.p)

    def test_fresh_nonces(self):
        nonces = set()
        for i in range(5):
            self.alice.start_exchange(self.p, self.g)
            nonces.add(self.alice.last_session.nonce_A)
        self.assertEqual(len(nonces), 5)

    def test_bob_has_no_secret_before_finish(self):
        message1 = self.alice.start_exchange(self.p, self.g)
        self.bob.handle_init(*message1)
        self.assertIsNone(self.bob.last_session.secret)

    def test_wrong_message_order(self):
        message1 = self.alice.start_exchange(self.p, self.g)
        message2 = self.bob.handle_init(*message1)
        message3 = self.alice.handle_response(*message2)
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(*message2)       # response sent to handle_init
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(*message1)  # init sent to Alice
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(*message3)  # finish sent to Alice
        other_alice, other_bob = make_sides()
        with self.assertRaises(ProtocolError):
            other_bob.handle_finish(*message3)     # finish with no session


if __name__ == "__main__":
    unittest.main()

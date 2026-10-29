import unittest
from authentication import ProtocolError, encode_message
from eve import (corrupt_signature, sign_with_eves_key, tamper,
                 unauthenticated_attack)
from parameters import find_generator, generate_prime
from participant import Participant, provision_trusted_keys
from protocol import AliceSide, BobSide


class TestUnauthenticated(unittest.TestCase):

    def test_eve_breaks_plain_dh(self):
        r = unauthenticated_attack()
        self.assertEqual(r["alice_secret"], 6)
        self.assertEqual(r["bob_secret"], 15)
        self.assertNotEqual(r["alice_secret"], r["bob_secret"])
        self.assertEqual(r["eve_with_alice"], 6)
        self.assertEqual(r["eve_with_bob"], 15)


class TestAuthenticated(unittest.TestCase):

    def setUp(self):
        alice = Participant("Alice")
        bob = Participant("Bob")
        provision_trusted_keys(alice, bob)
        self.alice = AliceSide(alice)
        self.bob = BobSide(bob)
        self.p = generate_prime(16)
        self.g = find_generator(self.p)

    def message1(self):
        return self.alice.start_exchange(self.p, self.g)

    def message2(self):
        return self.bob.handle_init(*self.message1())

    def other(self, value):
        # a different value that is still in range
        if value == 2:
            return 3
        return 2

    def test_modify_A(self):
        payload, signature = self.message1()
        changed = tamper(payload, ("A",), self.other(self.alice.last_session.public))
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(changed, signature)

    def test_modify_B(self):
        payload, signature = self.message2()
        changed = tamper(payload, ("transcript", "B"),
                         self.other(self.bob.last_session.public))
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(changed, signature)
        self.assertEqual(self.alice.last_session.state, "aborted")

    def test_modify_p_or_g(self):
        payload, signature = self.message1()
        for field, value in (("p", 65521), ("g", self.g + 1)):
            with self.assertRaises(ProtocolError):
                self.bob.handle_init(tamper(payload, (field,), value), signature)

    def test_modify_identity_labels(self):
        payload, signature = self.message1()
        for field, value in (("initiator", "Bob"), ("responder", "Alice")):
            with self.assertRaises(ProtocolError):
                self.bob.handle_init(tamper(payload, (field,), value), signature)

    def test_corrupt_signature(self):
        payload, signature = self.message1()
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(payload, corrupt_signature(signature))

    def test_sign_as_alice_with_eves_key(self):
        payload, signature = self.message1()
        with self.assertRaises(ProtocolError):
            self.bob.handle_init(payload, sign_with_eves_key(payload))

    def test_replay_old_response(self):
        old_response = self.message2()
        self.alice.handle_response(*old_response)  # old exchange finishes
        self.alice.start_exchange(self.p, self.g)  # new session
        with self.assertRaises(ProtocolError):
            self.alice.handle_response(*old_response)

    def test_replay_old_finish(self):
        message3 = self.alice.handle_response(*self.message2())
        self.bob.handle_finish(*message3)
        self.bob.handle_init(*self.message1())  # new Bob session
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(*message3)

    def test_duplicate_finish(self):
        message3 = self.alice.handle_response(*self.message2())
        self.bob.handle_finish(*message3)
        with self.assertRaises(ProtocolError):
            self.bob.handle_finish(*message3)

    def test_bad_messages(self):
        payload, signature = self.message1()
        for bad in (b"garbage", b"{}", b"x" * 5000, encode_message({"A": 8})):
            with self.assertRaises(ProtocolError):
                self.bob.handle_init(bad, signature)


if __name__ == "__main__":
    unittest.main()

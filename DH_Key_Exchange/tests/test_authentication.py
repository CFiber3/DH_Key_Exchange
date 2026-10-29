import unittest
from authentication import (PROTOCOL, ProtocolError, check_message,
                            encode_message, sign_message, verify_message)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from participant import Participant, provision_trusted_keys

NONCE = "a" * 64


def init_message(**changes):
    message = {"protocol": PROTOCOL, "message_type": "init",
               "initiator": "Alice", "responder": "Bob",
               "p": 23, "g": 5, "A": 8, "nonce_A": NONCE}
    message.update(changes)
    return message


class TestEncoding(unittest.TestCase):

    def test_same_bytes_any_order(self):
        self.assertEqual(encode_message({"A": 8, "g": 5, "p": 23}),
                         encode_message({"p": 23, "g": 5, "A": 8}))
        self.assertEqual(encode_message({"p": 23, "g": 5, "A": 8}),
                         b'{"A":8,"g":5,"p":23}')


class TestCheckMessage(unittest.TestCase):

    def test_good_message(self):
        message = init_message()
        self.assertEqual(check_message(encode_message(message)), message)

    def test_too_big(self):
        with self.assertRaises(ProtocolError):
            check_message(b" " * 5000)

    def test_not_json(self):
        for payload in (b"hello", b"", b"[1]"):
            with self.assertRaises(ProtocolError):
                check_message(payload)

    def test_duplicate_key(self):
        text = encode_message(init_message()).decode()
        with self.assertRaises(ProtocolError):
            check_message((text[:-1] + ',"p":29}').encode())

    def test_extra_or_missing_field(self):
        with self.assertRaises(ProtocolError):
            check_message(encode_message(init_message(extra=1)))
        message = init_message()
        del message["A"]
        with self.assertRaises(ProtocolError):
            check_message(encode_message(message))

    def test_wrong_types(self):
        for bad in ("8", 8.0, True, None):
            with self.assertRaises(ProtocolError):
                check_message(encode_message(init_message(A=bad)))

    def test_bad_nonce(self):
        for bad in ("a" * 63, "g" * 64, 5):
            with self.assertRaises(ProtocolError):
                check_message(encode_message(init_message(nonce_A=bad)))

    def test_bad_labels(self):
        for changes in ({"initiator": "Bob"}, {"responder": "Eve"},
                        {"protocol": "other"}, {"message_type": "hello"}):
            with self.assertRaises(ProtocolError):
                check_message(encode_message(init_message(**changes)))


class TestSigning(unittest.TestCase):

    def setUp(self):
        self.alice = Participant("Alice")
        self.bob = Participant("Bob")
        provision_trusted_keys(self.alice, self.bob)

    def test_valid_signature(self):
        payload, signature = sign_message(self.alice, init_message())
        verify_message(self.bob, "Alice", payload, signature)  # no error

    def test_changed_message(self):
        payload, signature = sign_message(self.alice, init_message())
        with self.assertRaises(ProtocolError):
            verify_message(self.bob, "Alice", encode_message(init_message(A=9)),
                           signature)

    def test_wrong_key(self):
        payload = encode_message(init_message())
        eve_signature = Ed25519PrivateKey.generate().sign(payload)
        with self.assertRaises(ProtocolError):
            verify_message(self.bob, "Alice", payload, eve_signature)

    def test_unknown_sender(self):
        payload, signature = sign_message(self.alice, init_message())
        with self.assertRaises(ProtocolError):
            verify_message(self.bob, "Eve", payload, signature)


if __name__ == "__main__":
    unittest.main()

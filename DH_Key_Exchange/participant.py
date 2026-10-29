# participant.py
# Diffie-Hellman values and the Alice/Bob signing identities

import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from modular_math import modular_exponentiation


def generate_private_exponent(p):
    """Random private exponent from 2 to p-2."""
    return secrets.randbelow(p - 3) + 2


def check_public_value(value, p):
    """Raise an error unless 2 <= value <= p-2."""
    if type(value) is not int:
        raise TypeError("public value must be an integer")
    if value < 2 or value > p - 2:
        raise ValueError("public value must be between 2 and p-2")


def generate_key_pair(g, p, private_exponent=None):
    """Return (private exponent, public value)."""
    # a fixed exponent is only used for the test fixtures
    if private_exponent is not None:
        public = modular_exponentiation(g, private_exponent, p)
        check_public_value(public, p)
        return private_exponent, public

    # otherwise keep picking until the public value is in range
    while True:
        private = generate_private_exponent(p)
        public = modular_exponentiation(g, private, p)
        try:
            check_public_value(public, p)
            return private, public
        except ValueError:
            pass


def compute_shared_secret(peer_public, own_private, p):
    """Shared secret = peer_public^own_private mod p."""
    check_public_value(peer_public, p)
    return modular_exponentiation(peer_public, own_private, p)


class Participant:
    """Alice or Bob with a signing key that is made once."""

    def __init__(self, name):
        if name != "Alice" and name != "Bob":
            raise ValueError("name must be Alice or Bob")
        self.name = name
        self._signing_key = Ed25519PrivateKey.generate()
        self.verification_key = self._signing_key.public_key()
        self.trusted_keys = {}  # other person's name -> their real public key

    def sign(self, message_bytes):
        return self._signing_key.sign(message_bytes)


def provision_trusted_keys(alice, bob):
    """Give Alice and Bob each other's real public key (done before anything is sent)."""
    alice.trusted_keys["Bob"] = bob.verification_key
    bob.trusted_keys["Alice"] = alice.verification_key

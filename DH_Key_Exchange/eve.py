# eve.py
# Eve can see and change messages but she cannot touch the trusted keys

import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from authentication import encode_message
from participant import compute_shared_secret, generate_key_pair


def unauthenticated_attack(p=23, g=5, a=6, b=15, e1=3, e2=7):
    """Man-in-the-middle on plain Diffie-Hellman using the small fixture."""
    A = generate_key_pair(g, p, a)[1]
    B = generate_key_pair(g, p, b)[1]
    E1 = generate_key_pair(g, p, e1)[1]  # Eve sends this to Alice as "Bob"
    E2 = generate_key_pair(g, p, e2)[1]  # Eve sends this to Bob as "Alice"
    return {
        "A": A, "B": B, "E1": E1, "E2": E2,
        "alice_secret": compute_shared_secret(E1, a, p),
        "eve_with_alice": compute_shared_secret(A, e1, p),
        "bob_secret": compute_shared_secret(E2, b, p),
        "eve_with_bob": compute_shared_secret(B, e2, p),
    }


def tamper(payload, path, new_value):
    """Change one field in a message but leave the old signature alone."""
    message = json.loads(payload)
    target = message
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = new_value
    return encode_message(message)


def corrupt_signature(signature):
    """Flip one bit in a signature."""
    return bytes([signature[0] ^ 1]) + signature[1:]


def sign_with_eves_key(payload):
    """Sign with Eve's own key instead of Alice's or Bob's."""
    return Ed25519PrivateKey.generate().sign(payload)

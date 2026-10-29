# main.py
# Runs the demos and the timing. Use: python main.py > sample_output.txt

import platform
import sys
import time
from importlib.metadata import version

from authentication import ProtocolError
from eve import tamper, unauthenticated_attack
from parameters import find_generator, generate_prime, prime_factors
from participant import Participant, provision_trusted_keys
from protocol import AliceSide, BobSide


def timed(function, *args):
    """Return (result, seconds)."""
    start = time.perf_counter()
    result = function(*args)
    return result, time.perf_counter() - start


def run_exchange(alice_side, bob_side, bits, show=False):
    """Do one full exchange and return the timings and results."""
    p, t_prime = timed(generate_prime, bits)
    factors, t_factor = timed(prime_factors, p - 1)
    g, t_generator = timed(find_generator, p, factors)
    result = {"prime": t_prime, "factor": t_factor, "generator": t_generator,
              "authenticated": False, "match": False}

    if show:
        print("Requested prime size:", bits, "bits")
        print("Modulus: generated using library prime generator")
        print("Modulus bit length:", p.bit_length())

    try:
        message1 = alice_side.start_exchange(p, g)
        message2 = bob_side.handle_init(*message1)
        if show:
            print("Received modulus library validation: PASS")
            print("Generator: validated")
            print("Alice initiation signature: VALID")
        message3 = alice_side.handle_response(*message2)
        if show:
            print("Bob response signature: VALID")
        bob_session = bob_side.handle_finish(*message3)
        if show:
            print("Alice finish signature: VALID")
    except ProtocolError as error:
        print("Exchange rejected:", error)
        return result

    result["authenticated"] = True
    result["match"] = alice_side.last_session.secret == bob_session.secret
    if show:
        print("Transcript authenticated: YES")
        if result["match"]:
            print("Shared-secret equality in local test: PASS")
        else:
            print("Shared-secret equality in local test: FAIL")
        print("Explicit key confirmation: NOT IMPLEMENTED")
    return result


def unauthenticated_demo():
    r = unauthenticated_attack()
    print("Fixture: p = 23, g = 5, a = 6, b = 15, Eve e1 = 3, e2 = 7")
    print("Alice's A =", r["A"], "and Bob's B =", r["B"])
    print("Eve sends E1 =", r["E1"], "to Alice and E2 =", r["E2"], "to Bob")
    print("Alice computes", r["alice_secret"], "and Eve computes", r["eve_with_alice"])
    print("Bob computes", r["bob_secret"], "and Eve computes", r["eve_with_bob"])
    print("Alice and Bob have different secrets and Eve knows both.")


def authenticated_demo(alice_side, bob_side):
    p = generate_prime(16)
    g = find_generator(p)
    message1 = alice_side.start_exchange(p, g)
    payload, signature = bob_side.handle_init(*message1)

    # Eve changes B but she can't make a new signature
    real_B = bob_side.last_session.public
    fake_B = 2
    if real_B == 2:
        fake_B = 3
    changed = tamper(payload, ("transcript", "B"), fake_B)

    print("Eve modified Bob's public value.")
    try:
        alice_side.handle_response(changed, signature)
        print("ERROR: the changed message was accepted")
    except ProtocolError as error:
        print("Alice rejected the response:", error)
        print("Bob response signature: INVALID")
        print("Exchange aborted.")


def main():
    # Alice and Bob are made once and reused for every exchange
    alice = Participant("Alice")
    bob = Participant("Bob")
    provision_trusted_keys(alice, bob)
    alice_side = AliceSide(alice)
    bob_side = BobSide(bob)

    print("=== Successful authenticated exchange ===")
    run_exchange(alice_side, bob_side, 16, show=True)

    print()
    print("=== Eve vs. unauthenticated Diffie-Hellman ===")
    unauthenticated_demo()

    print()
    print("=== Eve vs. authenticated exchange ===")
    authenticated_demo(alice_side, bob_side)

    print()
    print("=== Performance ===")
    print("Python", sys.version.split()[0], "on", platform.platform())
    print("cryptography", version("cryptography"),
          "and pycryptodome", version("pycryptodome"))
    print("| Bits | Trial | Prime generation (s) | Factorization (s) | "
          "Generator search (s) | Authenticated | Secrets match |")
    print("|---|---|---|---|---|---|---|")
    for bits in (16, 24, 32):
        for trial in (1, 2, 3):
            r = run_exchange(alice_side, bob_side, bits)
            if r["authenticated"]:
                authenticated = "Yes"
            else:
                authenticated = "No"
            if r["match"]:
                match = "Yes"
            else:
                match = "No"
            print("|", bits, "|", trial, "|", format(r["prime"], ".6f"), "|",
                  format(r["factor"], ".6f"), "|", format(r["generator"], ".6f"),
                  "|", authenticated, "|", match, "|")
    print("Times change from run to run, these are just measurements.")


if __name__ == "__main__":
    main()

# parameters.py
# Prime generation, modulus validation, factoring p - 1, and generators

import secrets
from Crypto.Util.number import getPrime, isPrime
from modular_math import modular_exponentiation


def check_bits(bits):
    """Make sure the prime size is an int from 16 to 32."""
    if type(bits) is not int:
        raise TypeError("bits must be an integer")
    if bits < 16 or bits > 32:
        raise ValueError("prime size must be between 16 and 32 bits")


def generate_prime(bits=16):
    """Get a prime with exactly this many bits from the library."""
    check_bits(bits)
    p = getPrime(bits, randfunc=secrets.token_bytes)
    if p.bit_length() != bits or p % 2 == 0:
        raise ValueError("library gave a bad prime")
    return p


def validate_received_modulus(p, allow_fixture=False):
    """Check a modulus we received (type, size, then library prime check)."""
    if type(p) is not int:
        raise TypeError("modulus must be an integer")
    # allow_fixture is only for tests (like p = 23)
    if not allow_fixture:
        check_bits(p.bit_length())
    if not isPrime(p):
        raise ValueError("modulus is not prime")
    return True


def prime_factors(n):
    """Return the set of distinct prime factors of n."""
    if type(n) is not int:
        raise TypeError("n must be an integer")
    if n <= 0:
        raise ValueError("n must be positive")

    factors = set()

    # divide out the 2s first
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n = n // 2

    # then try odd divisors
    d = 3
    while d * d <= n:
        if n % d == 0:
            factors.add(d)
            while n % d == 0:
                n = n // d
        d = d + 2

    # whatever is left over is prime
    if n > 1:
        factors.add(n)
    return factors


def is_generator(g, p, factors):
    """Check g against every prime factor of p - 1."""
    if type(g) is not int:
        raise TypeError("g must be an integer")
    if g < 2 or g > p - 2:
        raise ValueError("g must be between 2 and p-2")
    for r in factors:
        if modular_exponentiation(g, (p - 1) // r, p) == 1:
            return False
    return True


def find_generator(p, factors=None):
    """Return the first generator of p (factors can be passed in)."""
    if type(p) is not int:
        raise TypeError("p must be an integer")
    if not isPrime(p):
        raise ValueError("p must be prime")
    if factors is None:
        factors = prime_factors(p - 1)
    for g in range(2, p - 1):
        if is_generator(g, p, factors):
            return g
    raise ValueError("no generator found")

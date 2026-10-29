# modular_math.py
# Square-and-multiply modular exponentiation


def modular_exponentiation(base, exponent, modulus):
    """Return base^exponent mod modulus."""
    # type() is not int also rejects True/False
    for value in (base, exponent, modulus):
        if type(value) is not int:
            raise TypeError("inputs must be integers")
    if exponent < 0:
        raise ValueError("exponent must not be negative")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1 % modulus
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
    return result

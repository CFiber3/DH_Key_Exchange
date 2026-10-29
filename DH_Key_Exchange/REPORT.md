# Authenticated Diffie-Hellman Key Exchange

This project simulates an authenticated Diffie-Hellman key exchange between Alice and Bob in Python. Eve can see and change messages, and the program shows that she can break plain Diffie-Hellman but not the authenticated version. Everything runs locally. There are no network sockets and no message encryption.

## Setup

I used Python 3.14. The packages I used are:

- cryptography: 50.0.2
- pycryptodome: 4.2.0

Install them with:

    python -m pip install cryptography pycryptodome

## How to run

Run the demo from the project folder:

    python main.py

To save the output to a file:

    python main.py > sample_output.txt

The demo prints a successful exchange, Eve attacking plain Diffie-Hellman, Eve failing against the authenticated exchange, and timing for 3 exchanges each at 16, 24, and 32 bits.

## How to run the tests

From the project folder:

    python -m unittest discover -s tests -t . -v

My result was:

    Ran 60 tests in 0.143s

    OK

## Files

- `modular_math.py` - square-and-multiply modular exponentiation
- `parameters.py` - prime generation with PyCryptodome, modulus validation, factoring p - 1, and finding a generator
- `participant.py` - Diffie-Hellman values and the signing keys for Alice and Bob
- `authentication.py` - encoding, checking, signing, and verifying messages
- `protocol.py` - the three signed messages and the session records
- `eve.py` - Eve's attacks
- `main.py` - runs the demos and the timing
- `tests/` - the automated tests

## What I wrote and what the libraries do

I wrote the modular exponentiation, the factoring of p - 1, the generator check, and the Diffie-Hellman math. PyCryptodome generates the primes and checks if they are prime. The `cryptography` package does the Ed25519 signatures. Python's `pow` is only used in the tests to check my answers.

## How the exchange works

1. Alice sends a signed message with p, g, A, and a nonce.
2. Bob checks the signature and the values, then sends back a signed message with the full transcript.
3. Alice checks Bob's signature and sends back a signed finish message with the same transcript.

Each side only works out the shared secret after it has checked the other side's signature. Alice and Bob get each other's real public keys before anything is sent, so Eve can't swap them out. If anything fails a check, the exchange stops and that session's secret is thrown away.

## Limitations

- The 16 to 32 bit primes are only for testing and are not secure.
- The last message is a signed acknowledgement. It does not prove Alice calculated the secret, so explicit key confirmation is not implemented.
- The public value checks (2 to p - 2) are basic checks and not everything a real system would do.
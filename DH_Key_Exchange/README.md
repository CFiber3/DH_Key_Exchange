# Report: Authenticated Diffie-Hellman Key Exchange

## Setup
Python 3 plus two packages:

    py -m pip install -r requirements.txt

Package versions used (fill in from `py -m pip show cryptography pycryptodome`):

- cryptography: 50.0.2
- pycryptodome: 4.2.0
- Python: 3.14
## 1. Algorithms

**Square-and-multiply.** This computes base^exponent mod modulus without ever building the huge power. It looks at the exponent one binary digit at a time. If the digit is 1, it multiplies the result by the current base. Then it squares the base and halves the exponent. It reduces mod the modulus after every step, so the numbers stay small. The loop runs about log(exponent) times.

**Prime generation.** PyCryptodome's `getPrime` makes the prime. My wrapper checks that the requested size is an integer from 16 to 32, and then checks that the prime has exactly that many bits and is odd. When Bob receives a modulus, he checks the type, the bit size, and then uses the library's `isPrime`.

**Factoring p - 1.** I use trial division. I divide out all the 2s first, then try odd numbers starting at 3, dividing out each factor completely and saving it once. I stop when the divisor squared is bigger than what is left. If something greater than 1 is left, it is also a prime factor.

**Generator check.** A number g is a generator if g^((p-1)/r) mod p is not 1 for every prime factor r of p - 1. My code tries g = 2, 3, 4, and so on until one passes.

**Diffie-Hellman.** Each side picks a private exponent between 2 and p - 2 using `secrets`. The public values are A = g^a mod p and B = g^b mod p. Alice's secret is B^a mod p and Bob's is A^b mod p, and these are equal.

**Authentication.** Alice and Bob each have an Ed25519 signing key. There are three signed messages: init, response, and finish. The response and finish both sign the full transcript (p, g, A, B, and both nonces). Messages are turned into bytes with sorted-key JSON so both sides get the same bytes.

## 2. Worked examples

- 5^6 mod 23 = 8. The exponent goes 6, 3, 1, 0 as it is halved.
- For p = 23, p - 1 = 22 = 2 * 11, so the factors are {2, 11}. g = 2 fails because 2^11 mod 23 = 1. g = 5 passes.
- With a = 6 and b = 15: A = 5^6 mod 23 = 8 and B = 5^15 mod 23 = 19. Alice computes 19^6 mod 23 = 2 and Bob computes 8^15 mod 23 = 2.
- Eve attack on plain Diffie-Hellman: Eve picks e1 = 3 and e2 = 7, so E1 = 10 and E2 = 17. Alice and Eve both get 6, and Bob and Eve both get 15. Alice and Bob end up with different secrets.

## 3. Test results

I ran `py -m unittest discover -s tests -t . -v` and got:

    Ran 60 tests in 0.143s

    OK

The tests cover modular exponentiation, prime generation, modulus validation, factoring, generator checks, key agreement, message checking, signatures, the full exchange, and each attack: changing A, B, p, g, or the names, a corrupted signature, signing with Eve's key, replayed responses and finishes, a duplicate finish, and bad or out-of-order messages.

Performance (from `py main.py`, 3 exchanges at each size):

| Bits | Prime generation (s) | Factorization (s) | Generator search (s) |
| 16 | 1 | 0.000488 | 0.000009 | 0.000339 | Yes | Yes |
| 16 | 2 | 0.000557 | 0.000007 | 0.000550 | Yes | Yes |
| 16 | 3 | 0.000539 | 0.000007 | 0.000499 | Yes | Yes |
| 24 | 1 | 0.001027 | 0.000007 | 0.001089 | Yes | Yes |
| 24 | 2 | 0.001577 | 0.000022 | 0.001013 | Yes | Yes |
| 24 | 3 | 0.001031 | 0.000040 | 0.000992 | Yes | Yes |
| 32 | 1 | 0.002142 | 0.000114 | 0.001254 | Yes | Yes |
| 32 | 2 | 0.001382 | 0.003625 | 0.001687 | Yes | Yes |
| 32 | 3 | 0.001242 | 0.003184 | 0.001438 | Yes | Yes |

Environment: Python 3.14, Windows, cryptography 50.0.2, pycryptodome 4.2.0.

The times changed a little from run to run, which is normal. 

## 4. Trust assumptions

Alice and Bob get each other's real public signing keys before anything is sent. Eve can read, change, and replay messages on the network, but she can't change those stored keys or see any private keys. Each side always verifies against the key it already had, never a key that came inside a message.

## 5. Limitations

- The 16 to 32 bit primes are only for the principle and are not secure.
- The last message is a signed acknowledgement. It does not prove that Alice calculated the secret, so explicit key confirmation is not implemented.
- The public value checks (2 to p - 2) are basic and not everything a real system checks.
- Bob does not remember old init messages. A replayed init gets a new response, but it cannot finish without a matching finish message.

## 6. Research comparison: finite-field Diffie-Hellman and ECDH

In this project each side computes the shared secret with modular exponentiation: raise a generator g to a private exponent, mod a prime p. Elliptic-curve Diffie-Hellman (ECDH) does the same job with scalar multiplication on a curve, which means adding a point to itself a secret number of times. Both depend on a discrete logarithm problem being hard. The best known attacks against good elliptic curves are much weaker than the attacks against finite fields, so ECDH gets the same security with much smaller keys. NIST SP 800-56A covers both kinds of schemes [1], and RFC 7748 defines the X25519 function that is widely used today [2].

This project uses 16 to 32 bit primes so that trial division can factor p - 1 and the tests run fast. Those sizes are not secure. For a modulus under 2^32, an attacker can find a private exponent with baby-step giant-step in roughly 65,000 steps. Real finite-field Diffie-Hellman uses primes of 2048 bits or more, and RFC 7919 lists standard groups for that [3].

Factoring p - 1 is also a limit of the classroom version. We need the prime factors of p - 1 to check that g generates the whole group, and that only works because p is small. Real systems use safe primes or published parameters where the group order is already known. ECDH does not need random primes or factoring at all, because a standard fixes the curve and its order.

Ephemeral ECDH (ECDHE) means both sides make new key-agreement keys for every session and delete them afterward. This gives forward secrecy. If someone steals a long-term signing key later, they still can't recover the secrets of old sessions, because those keys no longer exist. My program does something similar by using new private exponents and nonces for each exchange, while the Ed25519 signing keys stay the same.

ECDH still needs authentication. Key agreement by itself does not say who is on the other end, so an attacker in the middle can run one exchange with each side, which is what Eve does in my unauthenticated demo. TLS 1.3 handles this by signing the handshake transcript with long-term keys [4], which is the same idea as the signed transcript in this project. Ed25519 and X25519 both use elliptic curves, but one is for signatures and the other is for key agreement, so they are different algorithms with different keys.

Real applications use established protocols, validated parameters, and well-tested libraries because small mistakes, like not checking a public value or leaking timing information, can break math that is otherwise sound.

### References

- PyCryptodome prime generation and validation documentation:

https://www.pycryptodome.org/src/util/util#module-Crypto.Util.number

- Python secrets documentation:

https://docs.python.org/3/library/secrets.html

- Ed25519 signing and verification documentation:

https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/

- Elliptic-curve key exchange documentation:

https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/

- RFC 9528: Ephemeral Diffie-Hellman Over COSE:

https://www.rfc-editor.org/rfc/rfc9528.html
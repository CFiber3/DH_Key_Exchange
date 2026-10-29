# protocol.py
# The three signed messages and the session records
#   1. Alice -> Bob: init
#   2. Bob -> Alice: response
#   3. Alice -> Bob: finish
# Every message is a (payload, signature) tuple.

import secrets
from authentication import (PROTOCOL, ProtocolError, check_message,
                            sign_message, verify_message)
from parameters import is_generator, prime_factors, validate_received_modulus
from participant import (check_public_value, compute_shared_secret,
                         generate_key_pair)


class Session:
    """Everything one exchange needs to remember."""

    def __init__(self, p, g, private, public):
        self.p = p
        self.g = g
        self.private = private
        self.public = public
        self.peer_public = None
        self.nonce_A = None
        self.transcript = None
        self.secret = None
        self.state = "started"

    def abort(self):
        """Throw away everything we could still use."""
        self.private = None
        self.secret = None
        self.state = "aborted"


def new_nonce():
    return secrets.token_bytes(32).hex()


class AliceSide:
    def __init__(self, alice):
        self.alice = alice
        self.sessions = {}  # nonce_A -> Session
        self.last_session = None

    def start_exchange(self, p, g, private_exponent=None):
        """Make message 1."""
        a, A = generate_key_pair(g, p, private_exponent)
        session = Session(p, g, a, A)
        session.nonce_A = new_nonce()
        session.state = "init_sent"
        self.sessions[session.nonce_A] = session
        self.last_session = session
        return sign_message(self.alice, {
            "protocol": PROTOCOL, "message_type": "init",
            "initiator": "Alice", "responder": "Bob",
            "p": p, "g": g, "A": A, "nonce_A": session.nonce_A})

    def handle_response(self, payload, signature):
        """Check Bob's response and make message 3."""
        message = check_message(payload)
        if message["message_type"] != "response":
            raise ProtocolError("expected a response")
        t = message["transcript"]
        session = self.sessions.get(t["nonce_A"])
        if session is None or session.state != "init_sent":
            raise ProtocolError("no matching session")

        try:
            if t["p"] != session.p or t["g"] != session.g or t["A"] != session.public:
                raise ProtocolError("p, g, or A does not match the session")
            check_public_value(t["B"], session.p)
            verify_message(self.alice, "Bob", payload, signature)
            session.peer_public = t["B"]
            session.secret = compute_shared_secret(t["B"], session.private, session.p)
        except (ProtocolError, ValueError, TypeError) as error:
            session.abort()
            raise ProtocolError(str(error))

        session.state = "finished"
        return sign_message(self.alice, {"message_type": "finish", "transcript": t})


class BobSide:
    def __init__(self, bob):
        self.bob = bob
        self.sessions = {}  # nonce_B -> Session
        self.last_session = None

    def handle_init(self, payload, signature, allow_fixture=False,
                    private_exponent=None):
        """Check Alice's init and make message 2."""
        message = check_message(payload)
        if message["message_type"] != "init":
            raise ProtocolError("expected an init message")
        verify_message(self.bob, "Alice", payload, signature)

        p, g, A = message["p"], message["g"], message["A"]
        try:
            validate_received_modulus(p, allow_fixture=allow_fixture)
            if not is_generator(g, p, prime_factors(p - 1)):
                raise ProtocolError("g is not a generator")
            check_public_value(A, p)
            b, B = generate_key_pair(g, p, private_exponent)
        except (ValueError, TypeError) as error:
            raise ProtocolError(str(error))

        nonce_B = new_nonce()
        session = Session(p, g, b, B)
        session.peer_public = A
        session.nonce_A = message["nonce_A"]
        session.transcript = {
            "protocol": PROTOCOL, "initiator": "Alice", "responder": "Bob",
            "p": p, "g": g, "A": A, "B": B,
            "nonce_A": message["nonce_A"], "nonce_B": nonce_B}
        session.state = "response_sent"
        self.sessions[nonce_B] = session
        self.last_session = session
        return sign_message(self.bob, {
            "message_type": "response", "transcript": session.transcript})

    def handle_finish(self, payload, signature):
        """Check Alice's finish. Bob only gets his secret after this passes."""
        message = check_message(payload)
        if message["message_type"] != "finish":
            raise ProtocolError("expected a finish message")
        t = message["transcript"]
        session = self.sessions.get(t["nonce_B"])
        if session is None or session.state != "response_sent":
            raise ProtocolError("no matching session")

        try:
            if t != session.transcript:
                raise ProtocolError("transcript does not match the session")
            verify_message(self.bob, "Alice", payload, signature)
            session.secret = compute_shared_secret(
                session.peer_public, session.private, session.p)
        except (ProtocolError, ValueError, TypeError) as error:
            session.abort()
            raise ProtocolError(str(error))

        session.state = "complete"
        return session

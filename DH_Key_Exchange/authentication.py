# authentication.py
# Encoding, checking, signing, and verifying messages

import json
from cryptography.exceptions import InvalidSignature

PROTOCOL = "DH-CLASSROOM-AUTH-v1"
MAX_SIZE = 4096
MAX_NUMBER = 2 ** 32  # p is at most 32 bits so every number is smaller than this


class ProtocolError(Exception):
    """Raised when a message or session gets rejected."""


def encode_message(message):
    """Turn a dict into bytes the same way every time."""
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def no_duplicate_keys(pairs):
    """Used while reading JSON so repeated keys get rejected."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate key in message")
        result[key] = value
    return result


def check_number(value):
    # type() is not int also rejects True/False and we never turn strings into ints
    if type(value) is not int:
        raise ProtocolError("expected an integer")
    if value <= 0 or value >= MAX_NUMBER:
        raise ProtocolError("number is out of bounds")


def check_nonce(value):
    if type(value) is not str or len(value) != 64:
        raise ProtocolError("bad nonce")
    for character in value:
        if character not in "0123456789abcdef":
            raise ProtocolError("bad nonce")


def check_transcript(t):
    names = ["protocol", "initiator", "responder", "p", "g", "A", "B",
             "nonce_A", "nonce_B"]
    if type(t) is not dict or sorted(t) != sorted(names):
        raise ProtocolError("bad transcript fields")
    if t["protocol"] != PROTOCOL:
        raise ProtocolError("wrong protocol")
    if t["initiator"] != "Alice" or t["responder"] != "Bob":
        raise ProtocolError("wrong identity labels")
    for name in ["p", "g", "A", "B"]:
        check_number(t[name])
    check_nonce(t["nonce_A"])
    check_nonce(t["nonce_B"])


def check_message(payload):
    """Check the bytes we received and return the message as a dict."""
    if type(payload) is not bytes:
        raise ProtocolError("message must be bytes")
    if len(payload) > MAX_SIZE:
        raise ProtocolError("message is too big")
    try:
        message = json.loads(payload.decode("utf-8"),
                             object_pairs_hook=no_duplicate_keys)
    except ValueError:
        raise ProtocolError("message is not valid JSON")
    if type(message) is not dict:
        raise ProtocolError("message must be a JSON object")

    kind = message.get("message_type")
    if kind == "init":
        names = ["protocol", "message_type", "initiator", "responder",
                 "p", "g", "A", "nonce_A"]
        if sorted(message) != sorted(names):
            raise ProtocolError("bad init fields")
        if message["protocol"] != PROTOCOL:
            raise ProtocolError("wrong protocol")
        if message["initiator"] != "Alice" or message["responder"] != "Bob":
            raise ProtocolError("wrong identity labels")
        for name in ["p", "g", "A"]:
            check_number(message[name])
        check_nonce(message["nonce_A"])
    elif kind == "response" or kind == "finish":
        if sorted(message) != ["message_type", "transcript"]:
            raise ProtocolError("bad message fields")
        check_transcript(message["transcript"])
    else:
        raise ProtocolError("unknown message type")
    return message


def sign_message(participant, message):
    """Return (payload, signature). The signature is not inside the payload."""
    payload = encode_message(message)
    return payload, participant.sign(payload)


def verify_message(receiver, sender_name, payload, signature):
    """Check the signature using the key we already trust for the sender."""
    key = receiver.trusted_keys.get(sender_name)
    if key is None:
        raise ProtocolError("no trusted key for " + str(sender_name))
    if type(payload) is not bytes or type(signature) is not bytes:
        raise ProtocolError("payload and signature must be bytes")
    try:
        key.verify(signature, payload)  # returns nothing if it is good
    except InvalidSignature:
        raise ProtocolError("invalid signature")

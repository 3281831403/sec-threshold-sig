"""Shared fixtures for the threshold-signature exercise.

The fixtures only build deterministic test material: group parameters, a
degree-two Shamir sharing, public commitments and valid partial signatures.
They never call the functions under test, so an unimplemented src module still
collects cleanly and every test fails inside its first production call.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# A 256-bit safe prime group.  Q is prime, P = 2*Q + 1 is prime, and G = 4
# has order Q modulo P.
P = 105691714255508482121613639744579206110468084374417573448624699383685088663807
Q = 52845857127754241060806819872289603055234042187208786724312349691842544331903
G = 4

N = 5
THRESHOLD = 3

# f(x) = A0 + A1*x + A2*x**2 over GF(Q); the secret is f(0) = A0.
A0 = 0x5A17C3E9B24D806F
A1 = 0x0F1E2D3C4B5A6978
A2 = 0x1122334455667788


def _share(index: int) -> int:
    return (A0 + A1 * index + A2 * index * index) % Q


SHARES = {index: _share(index) for index in range(1, N + 1)}
COMMITMENTS = {index: pow(G, share, P) for index, share in SHARES.items()}


def _message_scalar(message: str, q: int) -> int:
    raw = message.encode("utf-8")
    material = b"thsig/msg/v1" + len(raw).to_bytes(4, "big") + raw
    return int.from_bytes(hashlib.sha256(material).digest(), "big") % q


@pytest.fixture()
def params() -> dict:
    public = {
        "n": N,
        "p": P,
        "q": Q,
        "g": G,
        "commitments": dict(COMMITMENTS),
    }
    return {
        "p": P,
        "q": Q,
        "g": G,
        "n": N,
        "threshold": THRESHOLD,
        "shares": dict(SHARES),
        "public": public,
    }


@pytest.fixture()
def partial_for(params):
    def make(message: str, index: int) -> dict:
        salt = _message_scalar(message, params["q"])
        share = params["shares"][index] * salt % params["q"]
        return {"index": index, "share": share, "public": params["public"]}

    return make


@pytest.fixture()
def partials_for(partial_for):
    def make(message: str, indices) -> list:
        return [partial_for(message, index) for index in indices]

    return make


@pytest.fixture()
def policy() -> dict:
    return {"threshold": THRESHOLD, "verify_shares": True, "bind_message": True}
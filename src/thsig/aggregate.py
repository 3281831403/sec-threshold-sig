"""Threshold-signature share aggregation.

All eight public functions are implemented per the contract in README.md.
Every security-relevant check is enforced locally:

* digests and share verification bind both the message and the index;
* deduplication and threshold counting use distinct indices only;
* aggregation verifies every individual share and rejects equivocation;
* the aggregate signature carries its participating index set and the
  aggregate verification re-derives the group key from those indices;
* out-of-range indices and non-strict-integer types are rejected;
* policy validation refuses thresholds below two;
* batch aggregation keeps per-request state fully independent.
"""

from __future__ import annotations

import hashlib

_DIGEST_DOMAIN = b"thsig/digest/v1"
_MESSAGE_DOMAIN = b"thsig/msg/v1"


def _message_scalar(message, q) -> int:
    """Map a message to a scalar modulo q using the protocol encoding."""
    raw = message.encode("utf-8")
    material = _MESSAGE_DOMAIN + len(raw).to_bytes(4, "big") + raw
    return int.from_bytes(hashlib.sha256(material).digest(), "big") % q


def _length_prefixed(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _is_strict_int(value) -> bool:
    # bool is a subclass of int; True/False must never be accepted as indices
    # or shares, so an exact type check is required.
    return type(value) is int


def _lagrange_coefficients(indices, q) -> dict:
    """Lagrange coefficients at x = 0 over GF(q), keyed by index."""
    coefficients = {}
    for i in indices:
        numerator = 1
        denominator = 1
        for j in indices:
            if j == i:
                continue
            numerator = (numerator * j) % q
            denominator = (denominator * (j - i)) % q
        coefficients[i] = numerator * pow(denominator, -1, q) % q
    return coefficients


def _interpolate_at_zero(indices, values, q) -> int:
    """Lagrange interpolation of scalar value(i) at x = 0 over GF(q)."""
    coefficients = _lagrange_coefficients(indices, q)
    return sum(
        (coefficients[i] * values[i]) % q for i in indices
    ) % q


def _interpolate_group_key(indices, commitments, p, q) -> int:
    """Derive Y = g**f(0) from commitments via multiplicative interpolation.

    Commitments are group elements C_i = g**f(i) mod p, so the additive
    Lagrange combination has to happen in the exponent:
    Y = product(C_i ** lambda_i) mod p with coefficients taken mod q.
    """
    coefficients = _lagrange_coefficients(indices, q)
    group_key = 1
    for i in indices:
        group_key = (group_key * pow(commitments[i], coefficients[i], p)) % p
    return group_key


def share_digest(message, index, share) -> str:
    """Return a deterministic digest binding message, index and share."""
    # Each component carries its own length prefix, so no message/index
    # boundary can collapse two distinct triples into one encoding.
    encoded = (
        _DIGEST_DOMAIN
        + _length_prefixed(message.encode("utf-8"))
        + _length_prefixed(str(index).encode("utf-8"))
        + _length_prefixed(str(share).encode("utf-8"))
    )
    return hashlib.sha256(encoded).hexdigest()


def verify_share(message, index, share, public) -> bool:
    """Return True only for an in-range, message-bound, valid share."""
    try:
        if not _is_strict_int(index) or not _is_strict_int(share):
            return False

        n = public["n"]
        p = public["p"]
        q = public["q"]
        g = public["g"]
        commitments = public["commitments"]

        if not (1 <= index <= n) or index not in commitments:
            return False
        if not (0 <= share < q):
            return False

        message_scalar = _message_scalar(message, q)
        # sigma_i = s_i * h mod q is equivalent in the exponent group to
        # g**sigma_i == C_i**h, which binds both the message (via h) and the
        # index (via C_i), so cross-message reuse and index substitution fail.
        return pow(g, share, p) == pow(commitments[index], message_scalar, p)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def dedup_partials(partials) -> list:
    """Collapse duplicate indices, keeping the first occurrence."""
    seen = set()
    unique = []
    for partial in partials:
        index = partial["index"]
        if index not in seen:
            seen.add(index)
            unique.append(partial)
    return unique


def threshold_met(partials, threshold) -> bool:
    """Return True only when enough distinct indices are present."""
    if not _is_strict_int(threshold) or threshold < 2:
        return False
    return len(dedup_partials(partials)) >= threshold


def aggregate(message, partials, threshold) -> dict:
    """Aggregate verified shares and report the participating indices."""
    if not _is_strict_int(threshold) or threshold < 2:
        raise ValueError("threshold must be a strict int >= 2")

    # Structural validation and equivocation detection happen before any
    # cryptographic check, so malformed or conflicting input never reaches
    # interpolation.
    share_by_index = {}
    for partial in partials:
        if not isinstance(partial, dict):
            raise ValueError("each partial must be a dict")
        index = partial.get("index")
        share = partial.get("share")
        public = partial.get("public")
        if not _is_strict_int(index) or not _is_strict_int(share):
            raise ValueError("index and share must be strict ints")
        if not isinstance(public, dict):
            raise ValueError("partial is missing public parameters")

        if not (1 <= index <= public["n"]):
            raise ValueError(f"index {index} is outside [1, {public['n']}]")
        if not (0 <= share < public["q"]):
            raise ValueError("share is outside [0, q)")

        if index in share_by_index:
            if share_by_index[index] != share:
                raise ValueError(f"equivocating shares for index {index}")
        else:
            share_by_index[index] = share

    unique = dedup_partials(partials)
    if len(unique) < threshold:
        raise ValueError(
            f"need {threshold} distinct indices, got {len(unique)}"
        )

    for partial in unique:
        if not verify_share(
            message, partial["index"], partial["share"], partial["public"]
        ):
            raise ValueError(f"share verification failed for index {partial['index']}")

    indices = sorted(partial["index"] for partial in unique)
    q = unique[0]["public"]["q"]
    signature = _interpolate_at_zero(indices, share_by_index, q)
    return {"signature": signature, "indices": indices}


def verify_aggregate(message, signature, public_set) -> bool:
    """Verify a threshold signature against a message and public set."""
    try:
        if not isinstance(signature, dict):
            return False
        if set(signature) != {"signature", "indices"}:
            return False

        signature_value = signature["signature"]
        indices = signature["indices"]
        if not _is_strict_int(signature_value):
            return False
        if not isinstance(indices, list) or not indices:
            return False
        if any(not _is_strict_int(index) for index in indices):
            return False
        if len(set(indices)) != len(indices):
            return False

        p = public_set["p"]
        q = public_set["q"]
        g = public_set["g"]
        n = public_set["n"]
        commitments = public_set["commitments"]

        for index in indices:
            if not (1 <= index <= n) or index not in commitments:
                return False
        if not (0 <= signature_value < q):
            return False

        message_scalar = _message_scalar(message, q)
        # Re-derive the group key Y = g**f(0) from the reported indices only,
        # then check g**sigma == Y**h.  The message scalar participates in the
        # check, so a signature replayed against another message fails.
        group_key = _interpolate_group_key(indices, commitments, p, q)
        return pow(g, signature_value, p) == pow(group_key, message_scalar, p)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def validate_policy(policy) -> list[str]:
    """Return security-policy issue codes in a stable order."""
    issues: list[str] = []

    threshold = policy.get("threshold")
    if not _is_strict_int(threshold) or threshold < 2:
        issues.append("threshold_below_two")
    if policy.get("verify_shares") is not True:
        issues.append("shares_not_verified")
    if policy.get("bind_message") is not True:
        issues.append("message_not_bound")

    return issues


def aggregate_batch(requests, policy) -> dict:
    """Aggregate independent requests without sharing state between them."""
    issues = validate_policy(policy)
    if issues:
        raise ValueError(f"invalid policy: {', '.join(issues)}")

    # Each request is handled by a fresh aggregate() call with only its own
    # partials; nothing is cached or carried over between requests.
    results = [
        aggregate(request["message"], request["partials"], policy["threshold"])
        for request in requests
    ]
    return {"results": results}

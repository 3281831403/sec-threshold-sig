"""Threshold-signature share aggregation.

The eight public functions below are deliberately left unimplemented.  The
test-suite defines the required behaviour; implement the functions without
weakening any of the security checks described in README.md.
"""

from __future__ import annotations


def share_digest(message, index, share) -> str:
    """Return a deterministic digest binding message, index and share."""
    raise NotImplementedError


def verify_share(message, index, share, public) -> bool:
    """Return True only for an in-range, message-bound, valid share."""
    raise NotImplementedError


def dedup_partials(partials) -> list:
    """Collapse duplicate indices, keeping the first occurrence."""
    raise NotImplementedError


def threshold_met(partials, threshold) -> bool:
    """Return True only when enough distinct indices are present."""
    raise NotImplementedError


def aggregate(message, partials, threshold) -> dict:
    """Aggregate verified shares and report the participating indices."""
    raise NotImplementedError


def verify_aggregate(message, signature, public_set) -> bool:
    """Verify a threshold signature against a message and public set."""
    raise NotImplementedError


def validate_policy(policy) -> list[str]:
    """Return security-policy issue codes in a stable order."""
    raise NotImplementedError


def aggregate_batch(requests, policy) -> dict:
    """Aggregate independent requests without sharing state between them."""
    raise NotImplementedError
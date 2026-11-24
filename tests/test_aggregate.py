"""Strict acceptance tests for the threshold-signature aggregator.

The first ten tests map one-to-one to the ten specification defects.  The last
five cover the positive path and the four mandatory invariants: duplicates
count once, a message mismatch is rejected, a short threshold fails, and
batches are independent.
"""

from __future__ import annotations

import pytest

from thsig.aggregate import (
    aggregate,
    aggregate_batch,
    dedup_partials,
    share_digest,
    threshold_met,
    validate_policy,
    verify_aggregate,
    verify_share,
)


def test_defect_01_share_digest_binds_message(params, partial_for):
    message = "wire/transfer/2026-11-19/alpha"
    other = "wire/transfer/2026-11-19/beta"
    share = params["shares"][1]

    digest = share_digest(message, 1, share)
    assert digest == share_digest(message, 1, share)
    assert len(digest) == 64
    assert digest == digest.lower()
    assert all(character in "0123456789abcdef" for character in digest)

    assert share_digest(other, 1, share) != digest
    assert share_digest(message + "x", 1, share) != digest

    mismatched = partial_for(other, 1)
    assert verify_share(message, 1, mismatched["share"], params["public"]) is False


def test_defect_02_share_digest_binds_index(params, partial_for):
    message = "wire/transfer/2026-11-19/index"
    share = params["shares"][1]

    first = share_digest(message, 1, share)
    assert first != share_digest(message, 2, share)
    assert first != share_digest(message, 5, share)

    # Length-prefixed encoding avoids message/index boundary collisions.
    assert share_digest("ab", 12, share) != share_digest("ab1", 2, share)

    substituted = partial_for(message, 1)
    assert verify_share(message, 2, substituted["share"], params["public"]) is False
    assert verify_share(message, 5, substituted["share"], params["public"]) is False


def test_defect_03_dedup_by_index_not_share_value(params):
    public = params["public"]
    one = {"index": 1, "share": 4242, "public": public}
    two = {"index": 2, "share": 4242, "public": public}
    one_again = {"index": 1, "share": 9999, "public": public}
    three = {"index": 3, "share": 31337, "public": public}

    deduped = dedup_partials([one, two, one_again, three, dict(two)])

    assert [partial["index"] for partial in deduped] == [1, 2, 3]
    assert len(deduped) == 3
    # Same index: first occurrence wins.  Same value at another index is not a
    # duplicate at all.
    assert deduped[0]["share"] == 4242
    assert deduped[1]["share"] == 4242


def test_defect_04_threshold_counts_unique_indices_only(partial_for):
    message = "wire/transfer/2026-11-19/threshold"
    first = partial_for(message, 1)
    second = partial_for(message, 2)
    third = partial_for(message, 3)

    inflated = [first, dict(first), dict(first), dict(first), dict(first)]
    assert len(inflated) == 5
    assert threshold_met(inflated, 2) is False
    assert threshold_met(inflated, 5) is False

    assert threshold_met([first, second], 2) is True
    assert threshold_met([first, second], 3) is False
    assert threshold_met([first, second, dict(first), dict(second)], 3) is False
    assert threshold_met([first, second, third], 3) is True


def test_defect_05_aggregate_verifies_each_share(params, partials_for):
    message = "wire/transfer/2026-11-19/forged"
    partials = partials_for(message, [1, 2, 3])

    forged = dict(partials[1])
    forged["share"] = (forged["share"] + 1) % params["q"]
    with pytest.raises(ValueError):
        aggregate(message, [partials[0], forged, partials[2]], 3)

    zero = dict(partials[1])
    zero["share"] = 0
    with pytest.raises(ValueError):
        aggregate(message, [partials[0], zero, partials[2]], 3)

    # A conflicting copy of an already-present index is equivocation, not a
    # harmless duplicate.
    conflict = [partials[0], partials[1], dict(partials[1]), partials[2]]
    conflict[2]["share"] = (conflict[2]["share"] + 7) % params["q"]
    with pytest.raises(ValueError):
        aggregate(message, conflict, 3)


def test_defect_06_aggregate_reports_participating_indices(params, partials_for):
    message = "wire/transfer/2026-11-19/audit"
    partials = partials_for(message, [1, 3, 5])

    result = aggregate(message, partials, 3)

    assert isinstance(result, dict)
    assert set(result) == {"signature", "indices"}
    assert result["indices"] == [1, 3, 5]
    assert isinstance(result["signature"], int)
    assert 0 <= result["signature"] < params["q"]
    assert verify_aggregate(message, result, params["public"]) is True

    shuffled = aggregate(message, [partials[2], partials[0], partials[1]], 3)
    assert shuffled["indices"] == [1, 3, 5]


def test_defect_07_verify_aggregate_binds_message(params, partials_for):
    message = "wire/transfer/2026-11-19/domain-a"
    other = "wire/transfer/2026-11-19/domain-b"
    signature = aggregate(message, partials_for(message, [1, 2, 3]), 3)

    assert verify_aggregate(message, signature, params["public"]) is True
    assert verify_aggregate(other, signature, params["public"]) is False
    assert verify_aggregate(message + " ", signature, params["public"]) is False

    replayed = {"signature": signature["signature"], "indices": [1, 2, 3]}
    assert verify_aggregate(other, replayed, params["public"]) is False


def test_defect_08_out_of_range_index_rejected(params, partial_for, partials_for):
    message = "wire/transfer/2026-11-19/bounds"
    valid = partial_for(message, 1)

    assert verify_share(message, 1, valid["share"], params["public"]) is True
    assert verify_share(message, 0, valid["share"], params["public"]) is False
    assert verify_share(message, -1, valid["share"], params["public"]) is False
    assert verify_share(message, params["n"] + 1, valid["share"], params["public"]) is False
    assert verify_share(message, True, valid["share"], params["public"]) is False

    beyond = partial_for(message, 1)
    beyond["index"] = params["n"] + 1
    with pytest.raises(ValueError):
        aggregate(
            message,
            [partial_for(message, 1), partial_for(message, 2), beyond],
            3,
        )

    zero_index = partial_for(message, 1)
    zero_index["index"] = 0
    with pytest.raises(ValueError):
        aggregate(
            message,
            [partial_for(message, 1), partial_for(message, 2), zero_index],
            3,
        )


def test_defect_09_policy_flags_threshold_below_two():
    valid = {"threshold": 3, "verify_shares": True, "bind_message": True}
    assert validate_policy(valid) == []

    assert validate_policy(
        {"threshold": 1, "verify_shares": True, "bind_message": True}
    ) == ["threshold_below_two"]
    assert validate_policy(
        {"threshold": 0, "verify_shares": True, "bind_message": True}
    ) == ["threshold_below_two"]

    assert validate_policy(
        {"threshold": 2, "verify_shares": False, "bind_message": True}
    ) == ["shares_not_verified"]
    assert validate_policy(
        {"threshold": 2, "verify_shares": True, "bind_message": False}
    ) == ["message_not_bound"]
    assert validate_policy({"threshold": 3}) == [
        "shares_not_verified",
        "message_not_bound",
    ]
    assert validate_policy(
        {"threshold": 1, "verify_shares": False, "bind_message": False}
    ) == ["threshold_below_two", "shares_not_verified", "message_not_bound"]


def test_defect_10_batch_requests_do_not_share_partials(
    params, partials_for, policy
):
    message_a = "wire/transfer/2026-11-19/batch-a"
    message_b = "wire/transfer/2026-11-19/batch-b"
    request_a = {"message": message_a, "partials": partials_for(message_a, [1, 2, 3])}
    request_b = {"message": message_b, "partials": partials_for(message_b, [2, 4, 5])}

    batch = aggregate_batch([request_a, request_b], policy)

    assert set(batch) == {"results"}
    results = batch["results"]
    assert len(results) == 2
    assert results[0] == aggregate(message_a, request_a["partials"], 3)
    assert results[1] == aggregate(message_b, request_b["partials"], 3)
    assert results[0]["indices"] == [1, 2, 3]
    assert results[1]["indices"] == [2, 4, 5]
    assert verify_aggregate(message_a, results[0], params["public"]) is True
    assert verify_aggregate(message_b, results[1], params["public"]) is True


def test_threshold_met_aggregate_succeeds_and_verifies(params, partials_for):
    message = "wire/transfer/2026-11-19/positive"
    partials = partials_for(message, [2, 3, 4])

    assert threshold_met(partials, 3) is True
    result = aggregate(message, partials, 3)

    assert result["indices"] == [2, 3, 4]
    assert verify_aggregate(message, result, params["public"]) is True

    larger = aggregate(message, partials_for(message, [1, 2, 3, 4]), 3)
    assert larger["indices"] == [1, 2, 3, 4]
    assert verify_aggregate(message, larger, params["public"]) is True


def test_below_threshold_aggregation_fails(partials_for):
    message = "wire/transfer/2026-11-19/short"
    partials = partials_for(message, [1, 2])

    assert threshold_met(partials, 3) is False
    with pytest.raises(ValueError):
        aggregate(message, partials, 3)
    with pytest.raises(ValueError):
        aggregate(message, [], 3)


def test_duplicate_partials_counted_once(params, partials_for):
    message = "wire/transfer/2026-11-19/duplicates"
    base = partials_for(message, [1, 2, 3])
    duplicated = [
        base[0],
        dict(base[0]),
        base[1],
        dict(base[1]),
        base[2],
        dict(base[2]),
    ]

    assert len(duplicated) == 6
    assert threshold_met(duplicated, 3) is True
    result = aggregate(message, duplicated, 3)
    assert result["indices"] == [1, 2, 3]
    assert verify_aggregate(message, result, params["public"]) is True

    assert threshold_met(duplicated, 4) is False
    with pytest.raises(ValueError):
        aggregate(message, duplicated, 4)


def test_message_mismatched_partial_rejected(params, partials_for):
    message_a = "wire/transfer/2026-11-19/mismatch-a"
    message_b = "wire/transfer/2026-11-19/mismatch-b"
    valid_for_a = partials_for(message_a, [1, 2])
    valid_for_b = partials_for(message_b, [3])
    combined = valid_for_a + valid_for_b

    assert len(combined) == 3
    assert verify_share(
        message_a,
        3,
        valid_for_b[0]["share"],
        params["public"],
    ) is False
    with pytest.raises(ValueError):
        aggregate(message_a, combined, 3)
    with pytest.raises(ValueError):
        aggregate(message_b, combined, 3)


def test_batch_results_match_individual_aggregation(params, partials_for, policy):
    messages = [
        "wire/transfer/2026-11-19/equal-a",
        "wire/transfer/2026-11-19/equal-b",
        "wire/transfer/2026-11-19/equal-c",
    ]
    requests = [
        {"message": messages[0], "partials": partials_for(messages[0], [1, 2, 3])},
        {"message": messages[1], "partials": partials_for(messages[1], [2, 3, 4])},
        {"message": messages[2], "partials": partials_for(messages[2], [1, 4, 5])},
    ]

    batch = aggregate_batch(requests, policy)
    individual = [
        aggregate(request["message"], request["partials"], policy["threshold"])
        for request in requests
    ]

    assert batch["results"] == individual
    for message, result in zip(messages, batch["results"]):
        assert verify_aggregate(message, result, params["public"]) is True

    reversed_batch = aggregate_batch(list(reversed(requests)), policy)
    assert reversed_batch["results"] == list(reversed(individual))
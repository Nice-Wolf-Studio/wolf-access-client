"""RFC 8785 (JCS) canonical JSON and `diff_hash` (SHA-256 of it): kept from
0.5.0 as standalone helpers (the sign-off calls they served are gone).
"""
import hashlib

import pytest

from wolf_access_client import canonical_json, diff_hash


def test_jcs_sorts_keys_by_utf16_and_drops_whitespace():
    assert canonical_json({"b": 1, "a": [True, None, "x"], "€": 0, "\U0001f600": 0}) \
        == '{"a":[true,null,"x"],"b":1,"€":0,"\U0001f600":0}'
    # UTF-16 order: U+1F600 (surrogates D83D...) sorts before U+FB01.
    assert canonical_json({"ﬁ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"ﬁ":1}'


def test_jcs_strings_escape_only_what_json_needs():
    assert canonical_json("a\"\\\n\t\x01é/") == '"a\\"\\\\\\n\\t\\u0001é/"'


@pytest.mark.parametrize("number, text", [
    (0, "0"), (-0.0, "0"), (1.0, "1"), (100, "100"), (1e21, "1e+21"), (1e20, "100000000000000000000"),
    (1.5, "1.5"), (0.000001, "0.000001"), (1e-7, "1e-7"), (123.456e-10, "1.23456e-8"),
    (-2.5e30, "-2.5e+30"), (9007199254740991, "9007199254740991"),
])
def test_jcs_numbers_follow_ecmascript(number, text):
    assert canonical_json(number) == text


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 2 ** 53 + 1, {1: "x"}, b"x"])
def test_jcs_refuses_what_has_no_canonical_form(bad):
    with pytest.raises(ValueError):
        canonical_json(bad)


def test_diff_hash_is_sha256_of_the_jcs_form():
    change = {"note": "n-1", "body": "hello", "n": 2}
    expected = hashlib.sha256(b'{"body":"hello","n":2,"note":"n-1"}').hexdigest()
    assert diff_hash(change) == expected
    assert diff_hash({"n": 2, "note": "n-1", "body": "hello"}) == expected
    assert diff_hash({**change, "body": "hello!"}) != expected

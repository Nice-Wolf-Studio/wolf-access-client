"""RFC 8785 JSON Canonicalization Scheme (JCS) and `diff_hash`, the SHA-256
of a value's JCS form. Standalone helpers: the 0.5.0 sign-off calls they
were written for are gone with the routes (0.7.0).

`canonical_json` accepts the JSON data model only: dict with str keys,
list / tuple, str, bool, None, int within ±(2**53 - 1) (an I-JSON number,
RFC 7493) and finite float. Object members are sorted by the UTF-16 code
units of their names; strings escape only `"`, `\\` and control characters
(`\\b \\t \\n \\f \\r`, else `\\u00xx`); numbers use the ECMAScript
Number-to-String form (RFC 8785 §3.2.2.3)."""
from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

MAX_SAFE_INTEGER = 2 ** 53 - 1
_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f",
          "\r": "\\r"}


def _string(value: str) -> str:
    out = []
    for ch in value:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _number(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("JCS has no form for NaN or infinity")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits_t, exp = Decimal(repr(abs(value))).as_tuple()[1:]
    digits = "".join(map(str, digits_t)).rstrip("0") or "0"
    exp += len(digits_t) - len(digits)          # trailing zeros moved to the exponent
    k, n = len(digits), len(digits) + exp       # value = 0.digits × 10**n
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        text = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e > 0 else "-") \
            + str(abs(e))
    return sign + text


def _utf16(name: str) -> bytes:
    return name.encode("utf-16-be", "surrogatepass")


def canonical_json(value: Any) -> str:
    """The RFC 8785 canonical JSON text of `value`."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("an integer beyond ±(2**53 - 1) has no exact JSON number form")
        return str(value)
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("JSON object names are strings")
        return "{" + ",".join(_string(k) + ":" + canonical_json(value[k])
                              for k in sorted(value, key=_utf16)) + "}"
    raise ValueError(f"{type(value).__name__} is not JSON data")


def diff_hash(change: Any) -> str:
    """The sign-off hash of a previewed change: lowercase hex SHA-256 of its
    JCS form, UTF-8 encoded (CLI-D4, CLI-P6)."""
    return hashlib.sha256(canonical_json(change).encode("utf-8")).hexdigest()


__all__ = ["canonical_json", "diff_hash"]

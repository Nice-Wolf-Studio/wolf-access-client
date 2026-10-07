"""Argument checks shared by the client and the values it takes."""

from __future__ import annotations

from typing import Any

#: Principal kinds an owner may be (API-D3).
PRINCIPAL_TYPES = ("user", "org", "relationship", "project", "agent")


def nonblank(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def require(**values: Any) -> None:
    for name, value in values.items():
        if not nonblank(value):
            raise ValueError(f"{name} must be a non-empty string")


def resource_type(value: Any) -> tuple[str, str]:
    """`<service>/<type>`: exactly one `/`, two non-empty parts, no whitespace."""
    if not isinstance(value, str):
        raise ValueError("resource_type must be '<service>/<type>'")
    service, sep, name = value.partition("/")
    if not sep or not service or not name or "/" in name or any(
            c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("resource_type must be '<service>/<type>'")
    return service, name


def service_name(value: Any) -> str:
    """A service name as it appears in `<service>/<type>` and in
    `/v1/services/{service}`: non-empty, no `/`, no whitespace or control
    characters."""
    if not isinstance(value, str) or not value or "/" in value or any(
            c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("service must be a service name such as 'wolfnotes'")
    return value

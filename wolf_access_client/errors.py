"""Every way a check can fail without an answer. Each one means deny / "not
found" to the caller (CLI-P2, fail closed), but it is raised, never returned,
so a caller can tell "wolf-access said no" apart from "no answer"."""


class WolfAccessError(Exception):
    """No decision was obtained. Treat as deny."""


class WolfAccessUnavailable(WolfAccessError):
    """wolf-access could not be reached, the TLS handshake failed, the HTTP
    exchange broke, or no answer came within the timeout. The cause is
    chained."""


class WolfAccessHTTPError(WolfAccessError):
    """wolf-access answered with a status other than 200 (redirects are not
    followed)."""

    def __init__(self, status: int) -> None:
        super().__init__(f"wolf-access answered HTTP {status}")
        self.status = status

    def __reduce__(self):  # noqa: ANN204  (pickle/copy rebuild from the status)
        return (type(self), (self.status,))


class WolfAccessResponseError(WolfAccessError):
    """wolf-access answered 200 but not with an AuthZEN evaluation response."""

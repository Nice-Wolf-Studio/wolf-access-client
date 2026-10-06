"""Every way a check can fail without an answer. Each one means deny / "not
found" to the caller (CLI-P2, fail closed), but it is raised, never returned,
so a caller can tell "wolf-access said no" apart from "no answer"."""


class WolfAccessError(Exception):
    """No decision was obtained. Treat as deny."""


class WolfAccessUnavailable(WolfAccessError):
    """wolf-access could not be reached, or did not answer in time."""


class WolfAccessHTTPError(WolfAccessError):
    """wolf-access answered with a non-2xx status (redirects are not followed)."""

    def __init__(self, status: int) -> None:
        super().__init__(f"wolf-access answered HTTP {status}")
        self.status = status


class WolfAccessResponseError(WolfAccessError):
    """wolf-access answered 2xx but not with an AuthZEN evaluation response."""

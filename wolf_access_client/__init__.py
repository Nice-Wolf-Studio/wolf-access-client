"""Python client library for wolf-access, the Nice-Wolf-Studio authorization
service. See README.md."""

from .client import Decision, WolfAccessClient
from .errors import (
    WolfAccessError,
    WolfAccessHTTPError,
    WolfAccessResponseError,
    WolfAccessUnavailable,
)

__version__ = "0.1.0"

__all__ = [
    "Decision", "WolfAccessClient", "WolfAccessError", "WolfAccessHTTPError",
    "WolfAccessResponseError", "WolfAccessUnavailable", "__version__",
]

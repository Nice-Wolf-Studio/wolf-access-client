"""Shared test values: the service the test client calls for, its
credential, and WRNs of the shapes wolf-access uses (built with `Wrn`, never
string literals: INT-B3)."""
from __future__ import annotations

from typing import Any

from wolf_access_client import WolfAccessClient, Wrn

SERVICE = "tasks"
CRED = "svc-credential-not-a-secret"

USER = Wrn("access", "user", "u1")
AGENT = Wrn("access", "agent", "a1")
APP = Wrn("access", "agent", "app1")          # the connected app (context.client_wrn)
ORG = Wrn("access", "org", "o1")
LIST = Wrn(SERVICE, "list", "l1")
TASK = Wrn(SERVICE, "task", "t1")
TASK2 = Wrn(SERVICE, "task", "t2")


def make(url: str, cred: Any = CRED, **kwargs: Any) -> WolfAccessClient:
    kwargs.setdefault("service", SERVICE)
    return WolfAccessClient(url, cred, **kwargs)

"""Enforcement modes for services that existed before wolf-access (CUT-D1,
CUT-S1), shared by every consumer so `off`, `shadow` and `on` mean the same
thing everywhere.

- `off`: today's behaviour. No decision call is made; everything is allowed.
- `shadow`: the decision is asked for, each deny is logged as `shadow_deny`,
  and the call is allowed. With wolf-access unreachable the call proceeds.
- `on`: enforced. A deny is a deny, and so is every failure to get an
  answer (CLI-P2, fail closed).

The mode switches only the decision path. The lifecycle outbox, intent
checks and ownership feed of CUT-D1 (1), (3) and (4) run in every mode and
arrive with wolf-access M1c (see README, "Not yet").
"""

from __future__ import annotations

import logging
import os
import re
from enum import Enum
from typing import Any, Iterable, Mapping

from .client import MAX_EVALUATIONS, WolfAccessClient
from .errors import AccessUnavailable, WolfAccessError
from .models import EvaluationItem

log = logging.getLogger("wolf_access_client")

_SERVICE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


class AccessMode(str, Enum):
    OFF = "off"
    SHADOW = "shadow"
    ON = "on"

    @classmethod
    def parse(cls, value: Any) -> "AccessMode":
        """The mode named exactly `off`, `shadow` or `on`; anything else is a
        `ValueError` (no case folding, no whitespace, no default)."""
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            for mode in cls:
                if mode.value == value:
                    return mode
        raise ValueError(f"access mode must be one of off, shadow, on; got {value!r}")

    @classmethod
    def from_env(cls, service: str, environ: Mapping[str, str] | None = None
                 ) -> "AccessMode":
        """Read `<SERVICE>_ACCESS_MODE` (e.g. `WOLFNOTES_ACCESS_MODE`) from
        `environ` (default: the process environment). Unset or empty is
        `off`, the CUT-S1 default; anything else but an exact mode name is a
        `ValueError`, so a typo never silently means `off`."""
        if not isinstance(service, str) or not _SERVICE.fullmatch(service):
            raise ValueError("service must be a name such as 'wolfnotes'")
        name = f"{service.upper()}_ACCESS_MODE"
        env = os.environ if environ is None else environ
        if not env.get(name):
            return cls.OFF
        try:
            return cls.parse(env[name])
        except ValueError:
            raise ValueError(f"{name}={env[name]!r} is not one of off, shadow, on") from None


class AccessGate:
    """Decisions under an enforcement mode. Build it once at start-up:
    `AccessGate(AccessMode.from_env("wolfnotes"), client)`. An unknown mode is
    refused here, and `shadow` and `on` need a client."""

    def __init__(self, mode: AccessMode | str, client: WolfAccessClient | None = None, *,
                 logger: logging.Logger | None = None) -> None:
        self._mode = AccessMode.parse(mode)
        if self._mode is not AccessMode.OFF and not isinstance(client, WolfAccessClient):
            raise ValueError(f"mode {self._mode.value} needs a WolfAccessClient")
        self._client = client
        self._log = logger or log

    @property
    def mode(self) -> AccessMode:
        return self._mode

    def check(self, *, user_id: str, client_id: str, action: str, resource_type: str,
              resource_id: str, context: Mapping[str, Any] | None = None) -> bool:
        """May the person do `action` on the resource, under this mode?"""
        if self._mode is AccessMode.OFF:
            return True
        where = {"user_id": user_id, "client_id": client_id, "action": action,
                 "resource_type": resource_type, "resource_id": resource_id}
        try:
            allowed = self._client.evaluation(context=context, **where).allowed  # type: ignore[union-attr]
        except (WolfAccessError, ValueError) as exc:
            return self._no_answer(exc, where)
        if allowed:
            return True
        if self._mode is AccessMode.SHADOW:
            self._shadow_deny(where)
            return True
        return False

    def filter(self, resource_ids: Iterable[str], *, user_id: str, client_id: str,
               action: str, resource_type: str,
               context: Mapping[str, Any] | None = None) -> list[str]:
        """The ids, in order, the person may `action` under this mode (`off`
        and `shadow` keep them all). Asks in batches of 1000; if any batch
        gets no answer, `on` keeps none."""
        ids = list(resource_ids)
        if self._mode is AccessMode.OFF or not ids:
            return ids
        where = {"user_id": user_id, "client_id": client_id, "action": action,
                 "resource_type": resource_type}
        decisions = []
        try:
            for start in range(0, len(ids), MAX_EVALUATIONS):
                decisions += self._client.evaluations(  # type: ignore[union-attr]
                    user_id=user_id, client_id=client_id, context=context,
                    items=[EvaluationItem(action, resource_type, rid)
                           for rid in ids[start:start + MAX_EVALUATIONS]])
        except (WolfAccessError, ValueError) as exc:
            return ids if self._no_answer(exc, where) else []
        kept = []
        for rid, decision in zip(ids, decisions, strict=True):
            if decision.allowed:
                kept.append(rid)
            elif self._mode is AccessMode.SHADOW:
                self._shadow_deny({**where, "resource_id": rid})
        return ids if self._mode is AccessMode.SHADOW else kept

    def _shadow_deny(self, where: dict[str, Any]) -> None:
        self._log.warning(
            "shadow_deny user_id=%s client_id=%s action=%s resource=%s:%s",
            where["user_id"], where["client_id"], where["action"], where["resource_type"],
            where["resource_id"], extra={"event": "shadow_deny", **where})

    def _no_answer(self, exc: Exception, where: dict[str, Any]) -> bool:
        """Log a check that got no decision; True if the mode lets it through."""
        event = "access_unavailable" if isinstance(exc, AccessUnavailable) else \
            "invalid_request" if isinstance(exc, ValueError) else "access_error"
        self._log.warning("%s mode=%s error=%s action=%s resource_type=%s", event,
                          self._mode.value, type(exc).__name__, where["action"],
                          where["resource_type"],
                          extra={"event": event, "mode": self._mode.value,
                                 "error": type(exc).__name__, **where})
        return self._mode is AccessMode.SHADOW

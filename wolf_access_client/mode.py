"""Enforcement modes for services that existed before wolf-access (CUT-D1,
CUT-S1), shared by every consumer so `off`, `shadow` and `on` mean the same
thing everywhere.

- `off`: today's behaviour. No decision call is made; everything is allowed.
- `shadow`: the decision is asked for, each deny is logged as `shadow_deny`,
  and the call is allowed. With wolf-access unreachable the call proceeds.
- `on`: enforced. A deny is a deny, and so is every failure to get an
  answer (CLI-P2, fail closed).

The mode switches only the decision path. The lifecycle outbox of CUT-D1 (1)
(`outbox.py`, `relay.py`) runs in every mode. In `shadow` and `on` the gate
also gives no answer from stale data (CUT-D1 (2)): it asks the outbox store
which resources still have a row wolf-access has not applied, and after a
restart in `on` it answers nothing until the rows written before start-up are
applied. Intent checks (3) and the ownership feed (4) arrive with wolf-access
M1c-2 and M1c-3 (see README, "Seams").
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Mapping

from .client import MAX_EVALUATIONS, WolfAccessClient
from .errors import AccessUnavailable, SeedNotVerified, WolfAccessError
from .models import EvaluationItem, OutboxProgress, ResourceRef

log = logging.getLogger("wolf_access_client")

_SERVICE = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def safe(value: Any) -> str:
    """`value` as text for a log message, every control character (line
    breaks included) escaped, so no logged field can start a log line of its
    own (CWE-117, #29). Structured `extra` fields keep the raw value."""
    text = value if isinstance(value, str) else str(value)
    return _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group()) if ord(m.group()) < 0x100
                        else "\\u%04x" % ord(m.group()), text)


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


@dataclass(frozen=True)
class GateHealth:
    """What a service puts on its `/health` for the gate (#28; its HTTP status
    stays 200): `ok`, or `degraded` with a `reason`:

    - `unavailable`: the last decision call got no answer (CLI-P2);
    - `seed_not_verified`: wolf-access answers no decision until the
      service's seed is verified (CUT-D1);
    - `outbox_error`: the outbox store or the parent chain could not be read;
    - `restart_gate`: `on` after a restart, waiting for wolf-access to apply
      the rows written before start-up (CUT-D1 (2))."""

    status: str
    reason: str | None = None

    def as_dict(self) -> dict[str, str]:
        return {"status": self.status} if self.reason is None else \
            {"status": self.status, "reason": self.reason}


_OK = GateHealth("ok")


class AccessGate:
    """Decisions under an enforcement mode. Build it once at start-up:

        AccessGate(AccessMode.from_env("wolfnotes"), client, outbox=store,
                   ancestors=parent_chain)

    An unknown mode is refused here. `shadow` and `on` need a client, the
    service's `OutboxStore` (`outbox`) and `ancestors`, a callable giving the
    service's own parent chain of a resource (its parent, the parent's
    parent, ...: `ResourceRef`s; `lambda ref: ()` for types without parents).
    The chain is read only while some row is unapplied. `off` needs none of
    them and never reads the outbox."""

    def __init__(self, mode: AccessMode | str, client: WolfAccessClient | None = None, *,
                 outbox: Any = None,
                 ancestors: Callable[[ResourceRef], Iterable[ResourceRef]] | None = None,
                 logger: logging.Logger | None = None) -> None:
        self._mode = AccessMode.parse(mode)
        self._client = client
        self._outbox = outbox
        self._ancestors = ancestors
        self._log = logger or log
        self._decision_failure: str | None = None
        self._outbox_failure = False
        self._restart_open = self._mode is not AccessMode.ON
        self._restart_waited = False
        self._startup: int | None = None
        if self._mode is AccessMode.OFF:
            return
        name = self._mode.value
        if not isinstance(client, WolfAccessClient):
            raise ValueError(f"mode {name} needs a WolfAccessClient")
        if outbox is None or not callable(getattr(outbox, "progress", None)) \
                or not callable(getattr(outbox, "unapplied", None)):
            raise ValueError(f"mode {name} needs outbox=, the service's OutboxStore: no "
                             "answer is given from stale data (CUT-D1 (2))")
        if not callable(ancestors):
            raise ValueError(f"mode {name} needs ancestors=, the service's own parent chain "
                             "of a resource (lambda ref: () for types without parents)")
        if self._mode is AccessMode.ON:
            try:
                self._startup = outbox.progress().last_sequence     # the restart gate's mark
            except Exception as exc:  # noqa: BLE001  (the first read that works sets it)
                self._outbox_error(exc)

    @property
    def mode(self) -> AccessMode:
        return self._mode

    @property
    def health(self) -> GateHealth:
        """`ok`, or `degraded` with its reason (see `GateHealth`). Never raises."""
        if self._mode is AccessMode.OFF:
            return _OK
        if not self._restart_open:
            try:
                progress = self._outbox.progress()
                self._outbox_failure = False
                self._restart_gate_open(progress)
            except Exception as exc:  # noqa: BLE001
                self._outbox_error(exc)
        if self._outbox_failure:
            return GateHealth("degraded", "outbox_error")
        if not self._restart_open:
            return GateHealth("degraded", "restart_gate")
        if self._decision_failure:
            return GateHealth("degraded", self._decision_failure)
        return _OK

    def check(self, *, user_id: str, client_id: str, action: str, resource_type: str,
              resource_id: str, context: Mapping[str, Any] | None = None) -> bool:
        """May the person do `action` on the resource, under this mode?"""
        if self._mode is AccessMode.OFF:
            return True
        where = {"user_id": user_id, "client_id": client_id, "action": action,
                 "resource_type": resource_type, "resource_id": resource_id}
        ref = ResourceRef(resource_type, resource_id)
        reason = self._held([ref]).get(ref)
        if reason is not None:
            return self._withhold(where, reason)
        try:
            allowed = self._client.evaluation(context=context, **where).allowed  # type: ignore[union-attr]
        except (WolfAccessError, ValueError) as exc:
            return self._no_answer(exc, where)
        self._decision_failure = None
        if allowed:
            return True
        if self._mode is AccessMode.SHADOW:
            self._shadow_deny(where, "decision")
            return True
        return False

    def filter(self, resource_ids: Iterable[str], *, user_id: str, client_id: str,
               action: str, resource_type: str,
               context: Mapping[str, Any] | None = None) -> list[str]:
        """The ids, in order, the person may `action` under this mode.

        - `off` keeps them all and asks nothing.
        - `on` leaves out, without asking, every resource with an outbox row
          wolf-access has not applied (on itself or its parent chain, CUT-D1
          (2)); asks about the rest in batches of 1000 and keeps the allowed
          ones; keeps none if any batch gets no answer.
        - `shadow` never changes an answer: it keeps them all, like `off`, and
          logs what `on` would leave out (`shadow_deny`, `reason=stale` or
          `reason=decision`)."""
        ids = list(resource_ids)
        if self._mode is AccessMode.OFF or not ids:
            return ids
        where = {"user_id": user_id, "client_id": client_id, "action": action,
                 "resource_type": resource_type}
        held = self._held([ResourceRef(resource_type, rid) for rid in ids])
        asked = []
        for rid in ids:
            reason = held.get(ResourceRef(resource_type, rid))
            if reason is None:
                asked.append(rid)
            elif reason == "stale" and self._mode is AccessMode.SHADOW:
                self._shadow_deny({**where, "resource_id": rid}, reason)
        decisions = []
        try:
            for start in range(0, len(asked), MAX_EVALUATIONS):
                decisions += self._client.evaluations(  # type: ignore[union-attr]
                    user_id=user_id, client_id=client_id, context=context,
                    items=[EvaluationItem(action, resource_type, rid)
                           for rid in asked[start:start + MAX_EVALUATIONS]])
        except (WolfAccessError, ValueError) as exc:
            return ids if self._no_answer(exc, where) else []
        if asked:
            self._decision_failure = None
        answers = iter(decisions)
        kept = []
        for rid in ids:
            if ResourceRef(resource_type, rid) in held:
                continue
            if next(answers).allowed:
                kept.append(rid)
            elif self._mode is AccessMode.SHADOW:
                self._shadow_deny({**where, "resource_id": rid}, "decision")
        return ids if self._mode is AccessMode.SHADOW else kept

    def withheld(self, resources: Iterable[ResourceRef], *, user_id: str | None = None,
                 client_id: str | None = None,
                 action: str | None = None) -> set[ResourceRef]:
        """Those of `resources` to leave out of a search, list or count now,
        for a service that filters with a gate of its own (a search result, a
        provider's permitted set).

        - `on`: each with an outbox row wolf-access has not applied, on itself
          or above it (CUT-D1 (2)); all of them after a restart until the
          restart gate opens; all of them when the outbox cannot be read.
        - `shadow` never changes an answer: always empty. Each resource `on`
          would leave out for stale data is logged as `shadow_deny`
          (`reason=stale`), with `user_id`, `client_id` and `action` if given.
        - `off`: always empty, and the outbox is not read."""
        refs = list(resources)
        if not all(isinstance(ref, ResourceRef) for ref in refs):
            raise ValueError("resources must be ResourceRef values")
        if self._mode is AccessMode.OFF:
            return set()
        held = self._held(refs)
        if self._mode is AccessMode.SHADOW:
            for ref, reason in held.items():
                if reason == "stale":
                    self._shadow_deny({"user_id": user_id, "client_id": client_id,
                                       "action": action, "resource_type": ref.type,
                                       "resource_id": ref.id}, reason)
            return set()
        return set(held)

    def hints(self, hints: Iterable[Any]) -> list[Any]:
        """The hints to show now (CUT-D1 (2), WN-D3).

        - `on`: all of them once every outbox row is applied and the restart
          gate is open; none while any row is unapplied (a hint carries no
          resource id, so no stale resource can be singled out), before the
          restart gate opens, or when the outbox cannot be read.
        - `off` and `shadow`: none. Neither answers differently from today,
          and today has no hints."""
        items = list(hints)
        if self._mode is not AccessMode.ON or not items:
            return []
        try:
            progress: OutboxProgress = self._outbox.progress()
            self._outbox_failure = False
        except Exception as exc:  # noqa: BLE001  (no hint from what cannot be read)
            self._outbox_error(exc)
            return []
        if not self._restart_gate_open(progress) \
                or progress.applied_through < progress.last_sequence:
            return []
        return items

    # --- stale data and the restart gate (CUT-D1 (2)) ------------------------------------

    def _held(self, refs: list[ResourceRef]) -> dict[ResourceRef, str]:
        """Each of `refs` that gets no answer now, with the reason."""
        try:
            progress: OutboxProgress = self._outbox.progress()
            self._outbox_failure = False
            if not self._restart_gate_open(progress):
                return dict.fromkeys(refs, "restart_gate")
            if progress.applied_through >= progress.last_sequence:
                return {}
            chains = {ref: [ref, *self._chain(ref)] for ref in dict.fromkeys(refs)}
            stale = self._outbox.unapplied({a for chain in chains.values() for a in chain})
        except Exception as exc:  # noqa: BLE001  (no answer from what cannot be read)
            self._outbox_error(exc)
            return dict.fromkeys(refs, "outbox_error")
        return {ref: "stale" for ref, chain in chains.items()
                if any(a in stale for a in chain)}

    def _chain(self, ref: ResourceRef) -> list[ResourceRef]:
        chain = list(self._ancestors(ref))  # type: ignore[misc]
        if not all(isinstance(a, ResourceRef) for a in chain):
            raise ValueError("ancestors must give ResourceRef values")
        return chain

    def _restart_gate_open(self, progress: OutboxProgress) -> bool:
        if self._restart_open:
            return True
        if self._startup is None:
            self._startup = progress.last_sequence
        if progress.applied_through >= self._startup and progress.dead_letter is None:
            self._restart_open = True
            if self._restart_waited:
                self._log.info("restart_gate_open applied_through=%d", progress.applied_through,
                               extra={"event": "restart_gate_open"})
            return True
        self._restart_waited = True
        return False

    def _withhold(self, where: dict[str, Any], reason: str) -> bool:
        if reason == "stale" and self._mode is AccessMode.SHADOW:
            self._shadow_deny(where, reason)
        return self._mode is AccessMode.SHADOW

    def _outbox_error(self, exc: Exception) -> None:
        self._outbox_failure = True
        self._log.warning("outbox_error mode=%s error=%s", self._mode.value, type(exc).__name__,
                          extra={"event": "outbox_error", "mode": self._mode.value,
                                 "error": type(exc).__name__})

    # --- logging -----------------------------------------------------------------------------

    def _shadow_deny(self, where: dict[str, Any], reason: str) -> None:
        self._log.warning(
            "shadow_deny user_id=%s client_id=%s action=%s resource=%s:%s reason=%s",
            safe(where["user_id"]), safe(where["client_id"]), safe(where["action"]),
            safe(where["resource_type"]), safe(where["resource_id"]), reason,
            extra={"event": "shadow_deny", "reason": reason, **where})

    def _no_answer(self, exc: Exception, where: dict[str, Any]) -> bool:
        """Log a check that got no decision; True if the mode lets it through."""
        if isinstance(exc, ValueError):
            event = "invalid_request"
        else:
            event = "seed_not_verified" if isinstance(exc, SeedNotVerified) else \
                "access_unavailable" if isinstance(exc, AccessUnavailable) else "access_error"
            self._decision_failure = "seed_not_verified" if isinstance(exc, SeedNotVerified) \
                else "unavailable"
        self._log.warning("%s mode=%s error=%s action=%s resource_type=%s", event,
                          self._mode.value, type(exc).__name__, safe(where["action"]),
                          safe(where["resource_type"]),
                          extra={"event": event, "mode": self._mode.value,
                                 "error": type(exc).__name__, **where})
        return self._mode is AccessMode.SHADOW

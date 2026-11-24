# Architecture and Specification Decisions

## D-1: INT-D6 repair outbox uses per-service `reconcile` (`[default — changeable]`)

- **Status:** `[default — changeable]` (resolves [#51](https://github.com/Nice-Wolf-Studio/wolf-access-client/issues/51))
- **Spec refs:** `INT-D6`, `INT-D7`, `AC-3`, `AC-14`, `CUT-D1`

### Context

`wolf-access-client` 0.7.0 (PR #52, `5c419d5`) removed the 0.6.0 outbox/relay/gate modules (`outbox.py`, `relay.py`, `mode.py`) because `wolf-access` PR #329 removed `POST /v1/services/{service}/changes` and `/state`. Under the redesigned API, synchronous tree writes (`INT-D3`) are the primary path, and replaying a `create` under a parent via `POST /v1/resources` requires the acting principal's exchanged token (`AC-3`, refused `401 unauthorized` without one), which an `(operation, wrn, parent_wrn, version)` row does not carry.

### Decision

1. **No shared outbox/relay in `wolf-access-client`.** `wolf_access_client` keeps `outbox.py`, `relay.py`, and `mode.py` removed (`tests/test_package.py::test_the_old_api_modules_are_gone`).
2. **Default repair path is per-service `reconcile` (`INT-D7`, `AC-14`).** When a synchronous write leaves an unknown outcome or local state needs repair, the service keeps its own local repair queue/flag and triggers `client.reconcile(resources)` with its full `(wrn, parent_wrn)` list using the service credential:
   - Missing additions (`create`) are applied immediately by `wolf-access` without requiring a principal's token (`AC-14`).
   - Moves and removals are recorded in `reconcile_changes` and wait for operator approval (`ReconcileChange`).
   - Grants are never removed by `reconcile`.
3. **Optional principal-token replay remains service-local.** A service that stores the acting principal (e.g. `created_by`) in its own database may still exchange a principal token (`client.exchange_token(..., ACCESS_AUDIENCE)`) and call `client.create_resource(..., principal_token=...)` directly if it chooses.

### Consequences

- Matches the repair pattern adopted by `wolf-finance` (`drain_repairs`) and `people` (`outbox.sweep`), while remaining compatible with `wolf-notes` (`created_by` principal-token replay).
- Marked `[default — changeable]`: if the owner later settles on a standardized library-managed outbox schema carrying the acting principal WRN, it can be introduced without breaking `reconcile`.

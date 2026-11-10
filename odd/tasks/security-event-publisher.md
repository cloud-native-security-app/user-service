# security-event-publisher (KAP-08)

- Engram topic: `odd/security-event-publisher/tasks` (project: `user-service`)
- Branch: `feature/security_event_publisher` (off origin/develop 974bf9c)
- Status: in progress (2026-11-10)
- Master plan: repo `infra`, `odd/tasks/kinesis-admin-panel.md` (task KAP-08). Mirror of the gateway (KAP-06) and nmap-service (KAP-07) work.

## Objective

user-service publishes an `audit.recorded` security event to the Kinesis stream `security-events` through a `SecurityEventPublisher` port for every audit log entry it writes, without ever failing or delaying the business operation or altering the audit row.

## Scope

- Port `SecurityEventPublisher`, envelope `SecurityEvent` (source `user-service`) with a typed constructor for `audit.recorded` that returns `Err` for schema-invalid values; partition key `actor_sub`.
- Adapters: Kinesis (`aws-sdk-kinesis` 1.125.0, same as gateway and nmap-service; honors `AWS_ENDPOINT_URL`), no-op, in-memory recorder.
- Config `SECURITY_EVENTS_STREAM_NAME` (optional; unset/blank = no-op + one startup info log; invalid = startup config error), plus optional `AWS_REGION` / `AWS_ENDPOINT_URL`.
- Emission after the transaction that wrote the audit entry commits, contract parity tests against `../broker/contracts`, LocalStack Kinesis test.
- Out of scope: the gateway consumer and admin routes (KAP-09), retries/outbox, schema changes, new audit actions.

## Constraints

- Kinesis failures never fail or delay the business operation; logs carry the event type only.
- An event is emitted only after the audit row is committed; rolled-back work emits nothing.
- Events carry no email, display name, credentials, encrypted material or free text.
- Every emitted event validates against `broker/contracts/security-event.schema.json`.
- Unit tests do not mutate the process environment, use the in-memory config lookup and have no wall-clock waits.
- Code comments and docs in neutral Spanish, identifiers in English, this doc in English like the other `odd/tasks` docs.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer. Review policy: decline (stored user policy; no permission or secret touched).

## Decisions

- D1 Failure isolation: same as the other services. `emit`/`emit_all` publish from a detached `tokio::spawn` task bounded by a 5 s timeout per event; the batch stops at the first failure; logs carry the event type only. A crash before the task runs can lose events (accepted: `audit_log` is the source of truth).
- D2 Emission lives in `Repository`, right after each audit write is durable: after `tx.commit()` in `reconcile_roles` and `record_scan_request`, after the autocommit `INSERT` in `append_audit_entry`. A rolled-back transaction never reaches the emit call. The publisher is injected with `Repository::with_security_events` (default: no-op).
- D3 `actor_sub` is `audit_log.user_id` of the entry: for `scan_requested` the user who requested the scan (the actor); for `role.granted`/`role.revoked` the user whose role changed (the subject; the change is made by the bootstrap list, there is no human actor). Documented in `audit::recorded_event`.
- D4 Actions without a mapping (only reachable through `append_audit_entry` with an arbitrary string) emit nothing and log a warning with the event type and field, never the value (conservative: the free-form action text could carry anything).
- D5 `occurred_at` is the time of emission, not `audit_log.recorded_at`; consumers order by arrival and may dedupe by `event_id` (Kinesis is at-least-once).
- D6 Config reads `AWS_REGION` and `AWS_ENDPOINT_URL` as optional, trimmed, blank = unset; without a region the default AWS provider chain resolves it. Credentials always come from the default chain, never from code.
- D7 Stream name validation as in nmap-service: `[a-zA-Z0-9_.-]`, up to 128 chars; the error names the variable, never the value.

## Mapping

| `audit_log.action` | `payload.action` | `payload.resource_type` | `actor_sub` |
|---|---|---|---|
| `scan_requested` | `scan.requested` | `scan` | requester `user_id` |
| `role.granted` | `role.granted` | `user` | user whose role changed |
| `role.revoked` | `role.revoked` | `user` | user whose role changed |
| anything else | not emitted (D4) | - | - |

## Checklist

- [x] SEP-01 Feature doc.
- [ ] SEP-02 `SecurityEvent` envelope, port, recorder/no-op adapters, `emit`/`emit_all`, `audit::recorded_event`, schema parity tests.
- [ ] SEP-03 Kinesis adapter, `SECURITY_EVENTS_STREAM_NAME`, wiring, LocalStack test.
- [ ] SEP-04 Emission after commit in the repository, with failing-publisher tests (repository and HTTP).
- [ ] SEP-05 `docs/decisions.md` (ADR-013), README env table, this doc closed.

## Evidence

(filled per task)

## Next step

KAP-09: gateway consumer of the stream and admin routes.

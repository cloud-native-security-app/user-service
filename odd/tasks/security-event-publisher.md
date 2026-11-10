# security-event-publisher (KAP-08)

- Engram topic: `odd/security-event-publisher/tasks` (project: `user-service`)
- Branch: `feature/security_event_publisher` (off origin/develop 974bf9c)
- Status: done (2026-11-10)
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

- [x] SEP-01 Feature doc (ab5647d).
- [x] SEP-02 `SecurityEvent` envelope, port, recorder/no-op adapters, `emit`/`emit_all`, `audit::recorded_event`, schema parity tests (404817c).
- [x] SEP-03 Kinesis adapter, `SECURITY_EVENTS_STREAM_NAME`, `AWS_REGION`/`AWS_ENDPOINT_URL`, wiring, LocalStack test (146fd8d).
- [x] SEP-04 Emission after commit in the repository, with failing-publisher tests (repository and HTTP) and an end-to-end Postgres + LocalStack test (ca18f0c).
- [x] SEP-05 `docs/decisions.md` (ADR-013), README env table, this doc closed (docs commit on top of ca18f0c).

## Emission points

| Event | Where | Condition |
|---|---|---|
| `audit.recorded` (`role.granted`/`role.revoked`) | `src/repository.rs` `Repository::reconcile_roles` (startup via `wiring::build_router`, and `PUT /users/me` via `reconcile_user_role`) | after `tx.commit()`, one per changed role |
| `audit.recorded` (`scan.requested`) | `Repository::record_scan_request` (`POST /users/me/scans`) | after `tx.commit()` |
| `audit.recorded` (mapped actions only) | `Repository::append_audit_entry` | after the autocommit `INSERT`; no caller in `src/` today |

All go through `Repository::emit_audit_recorded` -> `audit::recorded_event` -> `security_events::emit_all`.

## Evidence

- RED SEP-02: `cargo test --lib --no-run` failed with 45 compile errors (`SecurityEvent`, `emit`, `EventSource`, publishers not found) and the contract/audit tests did not compile. GREEN: 17 `security_events` unit tests (envelope, validation, partition key, no-op/recorder, `emit`/`emit_all` failure, batch stop, 5 s timeout with a paused clock, no runtime), 4 `audit::recorded_event` tests, 5 contract tests (`tests/security_event_contract.rs`: every mapped action validates against the schema, boundaries, the schema rejects invalid events, the 11 broker examples round-trip, the audit example equals the constructor output).
- RED SEP-03: `cargo test --lib --no-run` failed with 19 compile errors (`SECURITY_EVENTS_STREAM_NAME_VAR`, `AWS_REGION_VAR`, `security_events_stream_name` missing); the LocalStack test did not compile (`user_service::messaging` missing). GREEN: 4 config tests via `Config::from_lookup`; `cargo test --test kinesis_publisher_localstack -- --ignored` 2 passed (3 events read back with `actor_sub` as partition key and schema validation; missing stream gives `PublishFailed` without the body).
- RED SEP-04: with the tests written first, `record_scan_request_emits_...`, `append_audit_entry_emits_...`, `role_reconciliation_emits_...` and `post_scan_emits_scan_requested_...` failed (no event arrived); the rollback and failing-publisher tests passed as regression guards. GREEN after emitting from `Repository`: all pass, plus `tests/audit_events_localstack.rs` (real Postgres + real Kinesis: `role.granted` and `scan.requested` read back valid).
- Final: `make verify` exit 0 (fmt, clippy `-D warnings`, tests, ignored Docker suites: 50 api, 46 repository, plus the new Kinesis and end-to-end suites; all passed, `cargo doc`); `cargo test --lib` 81 passed on three consecutive runs. `cargo doc` keeps one warning that predates this feature (`api` links to private `validate_scan_update`).
- Review: none run (stored user policy: decline).

## Known limitations

- Events can be lost if the process dies before the spawned task publishes; no retry or outbox (D1).
- `occurred_at` is the emission time, not `audit_log.recorded_at` (D5).
- An audit action without a mapping is not published (D4); today every action written by the service is mapped.
- Deployment: the ECS task role needs `kinesis:PutRecord` on the stream and the task needs `SECURITY_EVENTS_STREAM_NAME` (infra repo, not changed here). `docs/architecture.md` and `docs/security-scope.md` do not exist in this repo (only `docs/decisions.md`), so ADR-013 carries the architecture note.

## Next step

KAP-09: gateway consumer of the stream and admin routes.

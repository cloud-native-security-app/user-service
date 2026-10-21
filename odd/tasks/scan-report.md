# scan-report (user-service part)

Feature id: `scan-report` | Branch: `feature/scan_report` | Option A (user decision 2026-10-20)

Master plan: repo `front`, path `odd/tasks/scan-report.md` (tasks SRP-01 user-service, SRP-02 gateway, SRP-03 front).
This document covers SRP-01 plus the failure-reason and cancelled-state follow-ups from `front/odd/tasks/sectioned-navigation.md`.

## Objective

Store the `ScanResult` of a completed scan with its history entry, expose it to its owner, and persist/expose the failure/cancellation reason and a `CANCELADO` status.

## Scope

- Migration `20261020120000_add_scan_result_and_cancelled.sql` (additive): `scan_history.result JSONB NULL`, `scan_history.failure_reason TEXT NULL`, `status` CHECK (text column, not a Postgres enum) extended with `CANCELADO`.
- `PATCH /scans/{scan_id}` accepts optional `result` and `failure_reason`.
- `GET /users/me/scans` entries gain `failure_reason`; never the result.
- New `GET /users/me/scans/{scan_id}/report`.
- Status changes are not audited today (only `scan_requested`); unchanged.
- Out of scope: gateway and front changes; utoipa (this service has no OpenAPI; the contract is documented in README and below).

## Tasks

- [x] T1 Tests first (repository + API + domain unit), recorded RED.
- [x] T2 Migration, domain (`Cancelado`, `failure_reason`, `StoredScanResult`), repository (`update_scan_outcome`, `find_scan_result`).
- [x] T3 API: validation, `PATCH` fields, report endpoint.
- [x] T4 README, migrations README, this document.
- [x] T5 `make verify`.

TDD: enabled (project config), runner `cargo test` / `cargo test -- --ignored` (Docker testcontainers).
Route: delegated direct, single writer.

## Evidence

- RED: after writing the tests and before any production code, `cargo test --no-run` failed to compile: `no variant ... Cancelado found for enum ScanStatus`, `struct ScanHistoryEntry has no field named failure_reason` (plus the missing `update_scan_outcome`/`find_scan_result`/`StoredScanResult` used by the integration tests).
- GREEN: `make verify` exit 0: unit 46 passed; integration (`--ignored`) api 38 passed, repository 30 passed, service_wiring 2 passed; fmt, clippy `-D warnings` and `cargo doc` clean.

## Contract (consumed by the gateway)

All routes require the same headers as today: `X-Gateway-Secret` (shared secret, else `401`) and `X-Forwarded-User` (`{"sub","email"}`, else `400`). Error bodies are `{"error": "<mensaje>"}`.

### Status update: `PATCH /scans/{scan_id}`

Request body (`application/json`):

```json
{
  "status": "PENDIENTE | EN_PROGRESO | COMPLETADO | FALLIDO | CANCELADO",
  "result": { "ports": [], "vulnerabilities": [] },
  "failure_reason": "texto"
}
```

- `status` required. `result` and `failure_reason` optional; the old `{"status": "..."}` payload keeps working.
- `result`: only with `COMPLETADO`; must be a JSON object; serialized size <= 262144 bytes (256 KiB). Stored verbatim (the gateway sends the `ScanResult` JSON as-is; user-service does not interpret it).
- `failure_reason`: only with `FALLIDO` or `CANCELADO`; not blank; <= 500 characters (Unicode scalar values).
- Terminal states are final: once the scan is `COMPLETADO`, `FALLIDO` or `CANCELADO`, any later PATCH (late `EN_PROGRESO`, retries, a different terminal status) is a no-op that keeps status, `result`, `failure_reason` and `updated_at`, and returns `204` (SQS is unordered and at-least-once). Enforced atomically in SQL (`UPDATE ... WHERE status NOT IN (terminals)`); `404`/`403` still apply for unknown/foreign scans.
- Replace semantics (between non-terminal updates): each PATCH sets `result` and `failure_reason` to exactly what is sent (absent = cleared). The gateway must send the `result` in the same PATCH that sets `COMPLETADO`.

Responses:

| Code | When |
|------|------|
| `204` | Updated, or no-op because the scan is already terminal (no body) |
| `400` | `result` on non-`COMPLETADO`; `result` not an object; `failure_reason` on other statuses; blank or >500-char `failure_reason`; malformed/unknown `status` (axum JSON rejection, 4xx) |
| `401` / `400` | Missing/invalid shared secret / missing identity header |
| `403` | Scan exists but belongs to another user |
| `404` | Scan does not exist |
| `413` | `result` serialized size > 256 KiB |

### History entry: `GET /users/me/scans` (200, array ordered by `requested_at` ascending)

```json
{
  "scan_id": "string",
  "user_id": "string",
  "target": "string",
  "status": "PENDIENTE | EN_PROGRESO | COMPLETADO | FALLIDO | CANCELADO",
  "requested_at": "RFC 3339",
  "updated_at": "RFC 3339",
  "failure_reason": "string | null"
}
```

`failure_reason` is always present (`null` when absent). The result is never included. `POST /users/me/scans` returns the same shape (`status: "PENDIENTE"`, `failure_reason: null`).

### Report: `GET /users/me/scans/{scan_id}/report`

| Code | When | Body |
|------|------|------|
| `200` | Scan is the caller's, `COMPLETADO` and has a stored result | The stored `result` JSON object, verbatim (no envelope) |
| `404` | Scan does not exist or is not the caller's (never `403`) | `{"error": ...}` |
| `409` | Scan is the caller's but not `COMPLETADO` with a result (pending, in progress, failed, cancelled, or completed without a result) | `{"error": "el reporte del escaneo aún no está disponible"}` |
| `401` / `400` | Missing/invalid shared secret / missing identity header | `{"error": ...}` |

## Deviations / notes

- `COMPLETADO` without `result` is accepted (backwards compatibility); its report answers `409`.
- `ApiError::NotFound` message is now the generic `el recurso solicitado no existe` (all 404 bodies).
- Follow-up GGA fixes: terminal-final rule, `Cancelado` in the DB-encoding round-trip test, generic NotFound message, failure_reason message built from `MAX_FAILURE_REASON_CHARS`. RED: 3 new tests failed before the SQL guard/message change (status overwritten `FALLIDO` vs `COMPLETADO`, old message); GREEN after.
- Report path chosen: `/users/me/scans/{scan_id}/report` (same collection prefix and identity model as the other per-user history routes).
- `sqlx` gained the `json` feature (JSONB <-> `serde_json::Value`); `Cargo.lock` unchanged except as cargo required.

# finding-port (KAP-07b, user-service part)

- Engram topic: `odd/finding-port/tasks` (project: `user-service`)
- Branch: `feature/finding_port` (off origin/develop)
- Sibling repos, same feature id: `broker` (contract, D-15), `nmap-service` (producer), `gateway` (relay and report).

## Objective

The stored scan result keeps the optional `port`/`protocol` of each `VulnFinding`, and `GET /users/me/scans/{scan_id}/report` returns them, so the report can say where a vulnerability is.

## Scope

- Verify (and pin with tests) that the stored result round-trips findings with a port, with `null` port and without port.
- Out of scope: typed validation of `result` (it stays an opaque JSON object), a migration, the other services.

## Findings (storage check)

- `scan_history.result` is `JSONB NULL` (migration `20261020120000_add_scan_result_and_cancelled.sql`), `StoredScanResult.result` is `Option<serde_json::Value>` and the PATCH validation only requires a JSON object up to 256 KiB. The report endpoint returns the stored value verbatim.
- Therefore no code change and no migration are needed: the storage is JSON, not columnar. The new fields round-trip by construction; this feature adds characterization tests so a future typed model cannot drop them.

## Constraints

- No process-env mutation in unit tests, no waits. Docs and comments in neutral Spanish, identifiers in English, this doc in English like the other `odd/tasks` docs.

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer.

## Checklist

| ID | Task | Done |
|---|---|---|
| FP-01 | Feature document | [ ] |
| FP-02 | Characterization tests: repository and report endpoint round trip with/without port | [ ] |
| FP-03 | Docs: ADR-014 | [ ] |
| FP-04 | `make verify` | [ ] |

## TDD note

There is no RED for FP-02: the behavior already holds because the result is opaque JSONB (see Findings). The tests are characterization tests; they would fail (RED) if the result were deserialized into a typed model that lacks the fields.

## Compatibility note

Nothing to deploy order-wise in this repo; gateway must be deployed before nmap-service (its `deny_unknown_fields`).

# user-role (KAP-04)

Feature id: `user-role` | Branch: `feature/user_role` (from `origin/develop` b664ed3)

Master plan: repo `infra`, path `odd/tasks/kinesis-admin-panel.md` (task KAP-04). The consumer is KAP-05 (gateway).

## Objective

Give each user a `role` (`user` or `admin`), expose it in the profile response the gateway reads at login, and bootstrap admins from `ADMIN_BOOTSTRAP_EMAILS`.

## Scope

- Migration: `users.role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin'))`.
- Domain: `Role` enum (`user`/`admin`, lowercase on the wire) and `UserProfile.role` in `GET`/`PUT /users/me`.
- The role is never read from a request body.
- Config `ADMIN_BOOTSTRAP_EMAILS` (comma-separated, trimmed, case-insensitive, unset/empty = no admins); an entry that is not an email is a startup config error.
- Reconciliation at startup (all rows) and at profile provisioning (`PUT /users/me`), granting and revoking.
- Every role change writes an `audit_log` entry (`role.granted` / `role.revoked`) in the same transaction.
- Out of scope: gateway changes (KAP-05), an admin UI to grant/revoke (plan, "Out of scope").

## Constraints

- Security-sensitive (authorization): no request path may write `role`.
- Audit entries carry no more personal data than today (`user_id`, plus the new role as `target`); no email.
- Applied migrations are never edited; `audit_log` stays append-only.
- Code comments and docs in neutral Spanish; identifiers in English; this doc in English like the other `odd/tasks` docs.

## Assumptions

- A1 (user decision): `ADMIN_BOOTSTRAP_EMAILS` is authoritative. A user is admin if and only if their email is in the list; removing an email revokes admin at the next startup or at that user's next provisioning.
- A2: the email is the one the gateway forwards in `X-Forwarded-User` (verified by the gateway), compared case-insensitively.
- A3: an empty entry between commas (`a@x.test,,b@x.test`, trailing comma) is skipped; a non-empty entry that is not an email shape fails startup.
- A4: `ms_usuarios_app` keeps its table-level `SELECT/INSERT/UPDATE` on `users` because provisioning-time promotion needs it. Least privilege is enforced in the application: `upsert_user` never writes `role`, and no handler accepts one.
- A5: the reconciliation uses the application pool (no new DB role or grant).

## Tooling

- TDD mode: on (source: user global config "Strict TDD Mode: enabled"); runner `make verify` (`cargo test -- --ignored` needs Docker).
- Route: delegated direct, single writer. Review policy: KAP-04 touches authorization, so a review is allowed.

## Checklist

- [x] UR-01 Feature doc (a4ad81f).
- [x] UR-02 Migration `20261109120000_add_user_role.sql`, `Role`, `UserProfile.role`, role never client-settable (76ac118).
- [x] UR-03 `AdminEmails`, config wiring, reconciliation at startup and provisioning, audit `role.granted`/`role.revoked` (4152e6d); fail-closed on non-UTF-8 list and bootstrap failure logged (a5dbc65).
- [x] UR-04 README (env var, profile contract), migrations README, ADR-012, this doc closed (docs commit on top of a5dbc65).

## Evidence

- RED UR-02: `cargo test --no-run` failed to compile: `cannot find type Role`, `struct UserProfile has no field named role`, `unresolved import user_service::domain::Role`.
- GREEN UR-02: `cargo test --lib` 49 passed; `cargo test -- --ignored` api 44, repository 36, service_wiring 2 passed; clippy `-D warnings` clean.
- RED UR-03: `cargo test --no-run` failed: `cannot find value ADMIN_BOOTSTRAP_EMAILS_VAR` (config tests) and the missing `AdminEmails`, `with_admin_emails`, `sync_admin_roles`, `reconcile_user_role`.
- GREEN UR-03: `cargo test --lib` 57 passed; `cargo test -- --ignored` api 47, repository 41, service_wiring 3 passed.
- RED a5dbc65: `from_env_fails_closed_when_admin_bootstrap_emails_is_not_valid_utf8` panicked (non-UTF-8 value silently meant "no admins"); GREEN after `read_admin_emails`.
- Final: `make verify` exit 0 (unit 58; integration api 47, repository 41, service_wiring 3). The `cargo doc` warning about `validate_scan_update` is pre-existing.
- Review: the pre-commit hook (gga) passed on every commit; its non-blocking notes (UserRow doc, SQLSTATE 23514 assertion, bootstrap failure log, non-UTF-8 handling) were addressed. No native `gentle-ai review` was run by the writer; KAP-04 touches authorization, so the parent should decide whether to assess/review.

## Design

- `users.role` (`user`/`admin`); `Role` in `domain`, lowercase on the wire; `GET`/`PUT /users/me` return `role`.
- `Repository::upsert_user` never writes `role`; `PUT /users/me` has no `role` field and ignores unknown ones.
- `AdminEmails` (domain, `Debug` shows only the count) parsed by `Config` from `ADMIN_BOOTSTRAP_EMAILS`; `Repository::sync_admin_roles` (startup, in `wiring::build_router`) and `reconcile_user_role` (after `upsert_user` in `PUT /users/me`) run one `UPDATE ... RETURNING` plus audit inserts in a single transaction, only for rows whose role changes.
- Audit: action `role.granted`/`role.revoked`, `user_id` the affected user, `target` the resulting role; no email.

## Gaps

- `GET /users/me` does not reconcile: a list change reaches a user at the next startup or the next `PUT /users/me` (the gateway provisions at login).
- The migration comment explains why `ms_usuarios_app` keeps table-level `UPDATE` on `users` (A4).

## Review

- 2026-11-10: native review granted by the user (medium risk, 14 files, 1054 lines, base `origin/develop`). One consolidated `review-reliability` lens. Result: **approved**, acknowledged (lineage `review-aef53cf2e093d082`). Three non-blocking advisory findings, kept as follow-ups:
  - R3-rolling-deploy-role-flapping (WARNING, `src/api.rs:274-280`): during a rolling deploy or a list change, replicas with different `ADMIN_BOOTSTRAP_EMAILS` reconcile in opposite directions on `PUT /users/me`, so a role can flip per replica and write extra audit entries.
  - R3-trim-lower-mismatch (SUGGESTION, `src/repository.rs:113-116`): `AdminEmails::contains` trims and uses Unicode lowercase; the SQL reconciliation uses `lower(email)` without trim. Normalize in one place or add a test with mixed case and surrounding whitespace.
  - R3-weak-append-only-assertion (SUGGESTION, `tests/repository.rs:1347`).

## Flaky unit test investigation

- Observed once: `cargo test --lib` reported `57 passed; 1 failed` right after the feature landed; the failing test name was not captured. Not reproduced in 26 later runs (7 sequential, 18 in parallel batches of 6, plus each test run alone).
- Suspect 1: `wiring::tests::build_router_returns_typed_error_when_migrations_database_is_unreachable` takes 30 s on every run because `migrate()` connects without `acquire_timeout`, so it relies on the sqlx default 30 s connect retry loop. Pre-existing (not introduced by KAP-04) and timing-dependent.
- Suspect 2: `config` tests mutate the process environment with `unsafe` `set_var`/`remove_var`. `ENV_MUTEX` serializes them against each other, but not against other tests in the same binary that may read the environment through C code (sqlx connection options, DNS resolution). KAP-04 added five more such tests, which raises the odds of a rare interleaving.
- Proposed fix (separate branch): give `migrate()` a short configurable `acquire_timeout`, and make `Config` loading testable without touching the global environment (a lookup function injected into `from_env`), so no test mutates the process env.

## Next step

KAP-05 in `gateway`: read `role` from `GET /users/me` at login and put it in the JWT.

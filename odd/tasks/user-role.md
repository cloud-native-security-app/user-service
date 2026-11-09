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

- [ ] UR-01 Feature doc.
- [ ] UR-02 Migration, `Role`, `UserProfile.role`, role never client-settable (tests first).
- [ ] UR-03 `AdminEmails`, config wiring, reconciliation at startup and provisioning, audit (tests first).
- [ ] UR-04 README, migrations README, ADR-012, this doc closed.

## Evidence

(filled per task)

## Next step

KAP-05 in `gateway`: read `role` from `GET /users/me` at login and put it in the JWT.

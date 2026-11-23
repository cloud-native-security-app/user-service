-- Task RF-01: reaper for report emails stuck in `pending`.
--
-- `report_email_claimed_at` records when a process claimed the send (set with
-- the `pending` claim and refreshed by each reaper re-claim). The reaper takes
-- `pending` rows whose claim is older than a threshold, so a send lost to a
-- shutdown or crash is retried. Rows claimed before this migration have NULL;
-- the reaper falls back to `updated_at` for them.
--
-- Additive and backwards compatible. `scan_history` already has table-level
-- `GRANT SELECT, INSERT, UPDATE` for `ms_usuarios_app`.

ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS report_email_claimed_at TIMESTAMPTZ NULL;

-- Keeps the reaper scan cheap: only `pending` rows are indexed.
CREATE INDEX IF NOT EXISTS scan_history_report_email_pending_idx
    ON scan_history (report_email_claimed_at)
    WHERE report_email_status = 'pending';

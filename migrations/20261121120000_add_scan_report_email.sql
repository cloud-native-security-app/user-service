-- Feature `report_email_on_completion` (EM-02): the history records whether the
-- report email of a completed scan was sent.
--
-- `report_email_status` is also the once-per-scan claim: the service sets it to
-- 'pending' with `UPDATE ... WHERE report_email_status IS NULL`, so a
-- redelivered completed outcome never sends a second email.
--
-- Additive and backwards compatible: both columns are NULL for existing rows.
-- `scan_history` already has table-level `GRANT SELECT, INSERT, UPDATE` for
-- `ms_usuarios_app`, which covers the new columns.

ALTER TABLE scan_history
    ADD COLUMN IF NOT EXISTS report_email_status TEXT NULL
    CHECK (report_email_status IN ('pending', 'sent', 'failed', 'disabled'));
ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS report_emailed_at TIMESTAMPTZ NULL;

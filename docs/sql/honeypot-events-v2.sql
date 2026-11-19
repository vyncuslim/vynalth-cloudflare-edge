-- Vynalth Honeypot: OPTIONAL schema expansion (v2)
-- Run manually in TiDB Cloud SQL Editor as the instance owner after review.
-- Do NOT run this from the Worker or commit passwords.
-- Existing records and the INSERT-only honeypot_writer grants are preserved.
-- These columns are nullable; v1 events remain valid and readable.
ALTER TABLE vynalth_honeypot.honeypot_events
  ADD COLUMN IF NOT EXISTS event_id CHAR(36) NULL,
  ADD COLUMN IF NOT EXISTS target_host VARCHAR(150) NULL,
  ADD COLUMN IF NOT EXISTS http_method VARCHAR(10) NULL,
  ADD COLUMN IF NOT EXISTS http_status SMALLINT UNSIGNED NULL,
  ADD COLUMN IF NOT EXISTS trap_kind VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS network_asn INT UNSIGNED NULL,
  ADD COLUMN IF NOT EXISTS edge_colo CHAR(3) NULL,
  ADD COLUMN IF NOT EXISTS bot_score TINYINT UNSIGNED NULL,
  ADD COLUMN IF NOT EXISTS verified_bot BOOLEAN NULL,
  ADD COLUMN IF NOT EXISTS ip_attribution VARCHAR(48) NULL,
  ADD COLUMN IF NOT EXISTS bot_claim VARCHAR(32) NULL,
  ADD COLUMN IF NOT EXISTS sample_rate DECIMAL(5,4) NULL;

-- Inspect the schema without changing records.
SHOW COLUMNS FROM vynalth_honeypot.honeypot_events;

-- Check whether a new row is from the Worker, not the old local_test:
SELECT id, observed_at, source, event_type, request_path,
       target_host, http_method, http_status, trap_kind,
       country_code, network_asn, bot_score, sample_rate
FROM vynalth_honeypot.honeypot_events
ORDER BY id DESC LIMIT 20;

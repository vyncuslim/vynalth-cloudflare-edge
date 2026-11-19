-- Vynalth Threat Intelligence Schema v1 — TiDB/MySQL-compatible.
-- REVIEW ONLY. No migration is executed by this PR.
-- This adds five new, initially empty tables; existing honeypot_events is
-- NOT modified or replaced. Current INSERT-only honeypot_writer grants stay intact.
-- Run only as a DB owner after backup review and explicit authorization.
USE vynalth_honeypot;

CREATE TABLE IF NOT EXISTS honeypot_sessions (
  session_id CHAR(36) NOT NULL PRIMARY KEY,
  sensor_id VARCHAR(80) NOT NULL,
  protocol VARCHAR(12) NOT NULL,
  source_ip_hash CHAR(64) NULL,
  start_time DATETIME(3) NOT NULL,
  end_time DATETIME(3) NULL,
  auth_attempts INT UNSIGNED NOT NULL DEFAULT 0,
  command_count INT UNSIGNED NOT NULL DEFAULT 0,
  tty_sha256 CHAR(64) NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'open',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_session_sensor_time (sensor_id, start_time),
  INDEX idx_session_status (status, start_time)
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
  artifact_id CHAR(36) NOT NULL PRIMARY KEY,
  session_id CHAR(36) NULL,
  event_row_id BIGINT NULL,
  artifact_kind VARCHAR(24) NOT NULL,
  content_sha256 CHAR(64) NOT NULL,
  size_bytes BIGINT UNSIGNED NULL,
  mime_hint VARCHAR(80) NULL,
  isolated_storage_ref VARCHAR(220) NULL,
  custody_state VARCHAR(24) NOT NULL DEFAULT 'quarantined',
  captured_at DATETIME(3) NOT NULL,
  retention_until DATETIME(3) NULL,
  reviewed_by VARCHAR(80) NULL,
  reviewed_at DATETIME(3) NULL,
  INDEX idx_evidence_session (session_id, captured_at),
  INDEX idx_evidence_hash (content_sha256),
  INDEX idx_evidence_retention (retention_until)
);

CREATE TABLE IF NOT EXISTS threat_indicators (
  indicator_id CHAR(36) NOT NULL PRIMARY KEY,
  indicator_type VARCHAR(16) NOT NULL,
  indicator_value VARCHAR(255) NOT NULL,
  source_artifact_id CHAR(36) NULL,
  first_seen DATETIME(3) NOT NULL,
  last_seen DATETIME(3) NOT NULL,
  valid_until DATETIME(3) NULL,
  review_status VARCHAR(24) NOT NULL DEFAULT 'candidate',
  confidence TINYINT UNSIGNED NULL,
  false_positive_status VARCHAR(24) NOT NULL DEFAULT 'unknown',
  tlp_label VARCHAR(20) NOT NULL DEFAULT 'TLP:AMBER',
  reviewer_id VARCHAR(80) NULL,
  reviewed_at DATETIME(3) NULL,
  share_authorized TINYINT NOT NULL DEFAULT 0,
  public_ip_release_approved TINYINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_indicator_review (review_status, reviewed_at),
  INDEX idx_indicator_value (indicator_type, indicator_value),
  INDEX idx_indicator_expiry (valid_until)
);

CREATE TABLE IF NOT EXISTS indicator_sightings (
  sighting_id CHAR(36) NOT NULL PRIMARY KEY,
  indicator_id CHAR(36) NOT NULL,
  sensor_id VARCHAR(80) NOT NULL,
  event_row_id BIGINT NULL,
  observed_at DATETIME(3) NOT NULL,
  observation_count INT UNSIGNED NOT NULL DEFAULT 1,
  sample_rate DECIMAL(5,4) NULL,
  assessment VARCHAR(24) NOT NULL DEFAULT 'unverified',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_sighting_indicator_time (indicator_id, observed_at),
  INDEX idx_sighting_sensor_time (sensor_id, observed_at)
);

CREATE TABLE IF NOT EXISTS intelligence_shares (
  share_id CHAR(36) NOT NULL PRIMARY KEY,
  partner_id VARCHAR(120) NOT NULL,
  indicator_id CHAR(36) NOT NULL,
  export_format VARCHAR(12) NOT NULL,
  purpose VARCHAR(200) NOT NULL,
  tlp_label VARCHAR(20) NOT NULL,
  status VARCHAR(24) NOT NULL DEFAULT 'requested',
  approved_by VARCHAR(80) NULL,
  approved_at DATETIME(3) NULL,
  exported_at DATETIME(3) NULL,
  payload_sha256 CHAR(64) NULL,
  revoked_at DATETIME(3) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_share_partner_time (partner_id, created_at),
  INDEX idx_share_indicator_status (indicator_id, status)
);

-- Privilege boundary: DO NOT grant UPDATE/SELECT/DELETE or new table access
-- to the Cloudflare honeypot_writer account. Analysis/export belongs to a
-- separate human-reviewed back-office identity with restricted access.
-- Neither CREATE TABLE nor grants happen automatically from GitHub CI.

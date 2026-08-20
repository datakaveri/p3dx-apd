-- APD Go — PostgreSQL Schema
-- Supports all 3 data access cases with AMD SEV-SNP TEE + runtime provider consent

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------

CREATE TYPE access_request_status AS ENUM (
    -- Phase 1: pre-approval
    'PENDING',
    'PRE_APPROVED',
    'REJECTED',
    -- Phase 2: TEE lifecycle
    'TEE_PROVISIONING',
    'AWAITING_ATTESTATION',
    'ATTESTATION_VERIFIED',
    'ATTESTATION_FAILED',
    -- Phase 3: runtime consent
    'AWAITING_RUNTIME_CONSENT',
    'RUNTIME_CONSENT_GRANTED',
    'CONSENT_DENIED',
    -- Phase 4+5: data access
    'KEY_RELEASED',
    'DATA_FETCHING',
    'COMPUTATION_COMPLETE',
    'RESULT_DELIVERED'
);

CREATE TYPE access_type AS ENUM (
    'OPEN',           -- Case 1: open folder / public URL
    'SSH_ENCRYPTED',  -- Case 2: SSH + decryption key
    'ENCRYPTED_ONLY'  -- Case 3: encrypted, no SSH
);

-- ---------------------------------------------------------------------------
-- Main access request table
-- ---------------------------------------------------------------------------

CREATE TABLE access_requests (
    id                      UUID PRIMARY KEY,
    consumer_id             UUID        NOT NULL,
    provider_id             UUID        NOT NULL,
    item_id                 UUID        NOT NULL,
    status                  access_request_status NOT NULL DEFAULT 'PENDING',
    access_type             access_type NOT NULL,

    -- Dataset & app metadata
    asset_name              TEXT        NOT NULL,
    asset_type              TEXT        NOT NULL DEFAULT '',
    resource_url            TEXT        NOT NULL,  -- where provider data lives
    app_image_id            TEXT        NOT NULL DEFAULT '',
    app_image_hash          TEXT        NOT NULL DEFAULT '',
    expected_measurement    TEXT        NOT NULL DEFAULT '', -- hex SHA-384 of trusted TEE binary
    consumer_public_key     TEXT        NOT NULL, -- result encrypted to this EC pub key

    -- Phase 1: pre-approval
    pre_approved_at         TIMESTAMPTZ,
    pre_approval_expiry     TIMESTAMPTZ,

    -- Phase 2: TEE provisioning
    tee_id                  TEXT,                -- ID assigned by TEE Orchestrator

    -- Phase 3: attestation
    -- TEE's ephemeral EC public key (from report_data). Provider encrypts key bundle to this.
    tee_public_key          TEXT,
    attestation_report      TEXT,                -- raw base64 SNP report (audit / non-repudiation)
    attestation_verified_at TIMESTAMPTZ,

    -- Phase 3: runtime consent
    consent_requested_at    TIMESTAMPTZ,
    consent_granted_at      TIMESTAMPTZ,

    -- Phase 5: result
    -- Encrypted with consumer's EC public key. APD stores ciphertext only.
    encrypted_result        TEXT,

    -- Flexible metadata (purpose, description, etc.)
    additional_info         JSONB,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_requests_consumer ON access_requests (consumer_id);
CREATE INDEX idx_access_requests_provider ON access_requests (provider_id);
CREATE INDEX idx_access_requests_status   ON access_requests (status);
CREATE INDEX idx_access_requests_item     ON access_requests (item_id);

-- Auto-update updated_at on every write
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_access_requests_updated_at
    BEFORE UPDATE ON access_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ---------------------------------------------------------------------------
-- One-time provider consent tokens
--
-- Sent via email link; consumed exactly once to approve/deny runtime consent.
-- Short TTL (30 min). Used column prevents replay even before expiry.
-- ---------------------------------------------------------------------------

CREATE TABLE consent_tokens (
    token       TEXT        PRIMARY KEY,     -- 64-char hex (32 random bytes)
    request_id  UUID        NOT NULL REFERENCES access_requests (id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_consent_tokens_request ON consent_tokens (request_id);
CREATE INDEX idx_consent_tokens_expiry  ON consent_tokens (expires_at)
    WHERE used = FALSE; -- partial index — only care about unexpired unused tokens

-- ---------------------------------------------------------------------------
-- Audit log
--
-- Immutable append-only log of every state transition and key relay event.
-- Key bundles are NEVER stored here; only metadata (who, when, requestId).
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    request_id  UUID        REFERENCES access_requests (id),
    actor_id    UUID,                       -- user who triggered the event (NULL for TEE)
    actor_type  TEXT        NOT NULL,       -- 'consumer' | 'provider' | 'tee' | 'apd'
    event       TEXT        NOT NULL,       -- e.g. 'ATTESTATION_VERIFIED', 'KEY_RELAYED'
    detail      JSONB,                      -- non-sensitive context (status from/to, teeId, etc.)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_request ON audit_log (request_id);
CREATE INDEX idx_audit_log_created ON audit_log (created_at);

-- ---------------------------------------------------------------------------
-- User client credentials
--
-- Hashed credentials for APD-issued API access tokens.
-- Only the hash is stored; plain-text returned once at creation.
-- ---------------------------------------------------------------------------

CREATE TABLE client_credentials (
    user_id     UUID        PRIMARY KEY,
    client_id   TEXT        NOT NULL UNIQUE,
    -- SHA-512 of the secret; never stored in plain text
    client_secret_hash TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------------------
-- FL form submissions
--
-- Store of record for FL output-owner form submissions, pushed here by aaa
-- (formSubmissions.service.js) at creation time. One row per form_id — a
-- re-submit for the same form_id overwrites the existing row in place.
-- Soft-deleted (immudb-style tombstone) rather than hard-deleted so history
-- isn't lost and reads can keep filtering on `deleted`.
-- ---------------------------------------------------------------------------

CREATE TABLE form_submissions (
    id                  TEXT        PRIMARY KEY,
    form_id             TEXT        NOT NULL,
    requested_by        TEXT        NOT NULL,
    output_owner_id     TEXT        NOT NULL,

    num_server_rounds   DOUBLE PRECISION,
    fraction_evaluate   DOUBLE PRECISION,
    local_epochs        DOUBLE PRECISION,
    learning_rate       DOUBLE PRECISION,
    batch_size          DOUBLE PRECISION,
    model               TEXT,
    framework           TEXT,
    components          JSONB       NOT NULL DEFAULT '{}',

    filled              BOOLEAN     NOT NULL DEFAULT TRUE,
    requested_at        TIMESTAMPTZ NOT NULL,
    filled_at           TIMESTAMPTZ NOT NULL,

    selected_providers  JSONB       NOT NULL DEFAULT '[]',
    ip_address          TEXT,
    port                DOUBLE PRECISION,
    ram_usage           DOUBLE PRECISION,

    deleted             BOOLEAN     NOT NULL DEFAULT FALSE,
    deleted_at          TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Only one live (non-deleted) row per form_id — mirrors the upsert-by-formId
-- behavior this table replaces from the old immudb store.
CREATE UNIQUE INDEX idx_form_submissions_form_id_live ON form_submissions (form_id) WHERE NOT deleted;
CREATE INDEX idx_form_submissions_created ON form_submissions (created_at);

CREATE TRIGGER trg_form_submissions_updated_at
    BEFORE UPDATE ON form_submissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ---------------------------------------------------------------------------
-- FL data-provider forms
--
-- Store of record for data-provider forms, pushed here by aaa. Insert-only —
-- unlike form_submissions there is no upsert-by-formId; every submit creates
-- a new row.
-- ---------------------------------------------------------------------------

CREATE TABLE provider_forms (
    id                  TEXT        PRIMARY KEY,
    form_id             TEXT,
    data_owner_id       TEXT,
    dataset_name        TEXT,

    ram                 DOUBLE PRECISION,
    memory_mb           DOUBLE PRECISION,
    data_size_bytes     DOUBLE PRECISION,
    data_resource_id    TEXT,
    ip_address          TEXT,
    port                DOUBLE PRECISION,
    ram_usage           DOUBLE PRECISION,

    filled              BOOLEAN     NOT NULL DEFAULT TRUE,
    filled_at           TIMESTAMPTZ NOT NULL,
    submitted_by        TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_provider_forms_form_id ON provider_forms (form_id);
CREATE INDEX idx_provider_forms_created ON provider_forms (created_at);

-- ---------------------------------------------------------------------------
-- Policies (Phase 0)
--
-- Access policies issued by the Contract Manager (ConMan)/data providers,
-- keyed by policyId. TOP queries by itemId before accepting a workload
-- contract. One row per policyId; querying by itemId returns the
-- most-recently-issued, non-expired policy for that dataset.
-- ---------------------------------------------------------------------------

CREATE TABLE policies (
    policy_id   TEXT        PRIMARY KEY,
    item_id     TEXT        NOT NULL,
    issued_by   TEXT        NOT NULL,
    rules       JSONB       NOT NULL DEFAULT '{}',
    is_private  BOOLEAN     NOT NULL DEFAULT false,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX idx_policies_item_id ON policies (item_id);

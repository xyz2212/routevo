CREATE TABLE IF NOT EXISTS identity_users (
    username VARCHAR(100) PRIMARY KEY,
    password VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE identity_users ALTER COLUMN username TYPE VARCHAR(254);
ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS display_name VARCHAR(120);
ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS phone VARCHAR(32);
ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS mfa_secret_ciphertext VARCHAR(256);
ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS mfa_enabled_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE identity_users ADD COLUMN IF NOT EXISTS mfa_setup_expires_at TIMESTAMP WITH TIME ZONE;
UPDATE identity_users SET display_name = username WHERE display_name IS NULL;
ALTER TABLE identity_users ALTER COLUMN display_name SET NOT NULL;

CREATE TABLE IF NOT EXISTS identity_user_roles (
    username VARCHAR(254) NOT NULL REFERENCES identity_users(username) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL,
    PRIMARY KEY (username, role)
);

CREATE TABLE IF NOT EXISTS identity_driver_applications (
    id UUID PRIMARY KEY,
    username VARCHAR(254) NOT NULL UNIQUE REFERENCES identity_users(username) ON DELETE CASCADE,
    vehicle_type VARCHAR(32) NOT NULL,
    service_area VARCHAR(120) NOT NULL,
    status VARCHAR(40) NOT NULL,
    submitted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    reviewed_by VARCHAR(254),
    reviewed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS identity_action_tokens (
    id UUID PRIMARY KEY,
    username VARCHAR(254) NOT NULL REFERENCES identity_users(username) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    purpose VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS identity_rate_limit_buckets (
    bucket_hash CHAR(64) PRIMARY KEY,
    window_started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    request_count INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_mfa_recovery_codes (
    id UUID PRIMARY KEY,
    username VARCHAR(254) NOT NULL REFERENCES identity_users(username) ON DELETE CASCADE,
    code_hash CHAR(64) NOT NULL UNIQUE,
    used_at TIMESTAMP WITH TIME ZONE
);

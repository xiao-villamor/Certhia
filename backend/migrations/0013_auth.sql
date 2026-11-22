CREATE TABLE auth_users (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE CHECK (email = lower(email)),
    display_name text NOT NULL,
    password_hash text,
    role text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    disabled boolean NOT NULL DEFAULT false
);

CREATE TABLE auth_identities (
    issuer text NOT NULL,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject),
    UNIQUE (user_id, issuer)
);

CREATE TABLE auth_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    idle_expires timestamptz NOT NULL,
    expires timestamptz NOT NULL
);
CREATE INDEX auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX auth_sessions_idle ON auth_sessions(idle_expires);

CREATE TABLE auth_oidc_flows (
    state_hash bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash) = 32),
    provider text NOT NULL,
    verifier text NOT NULL,
    nonce text NOT NULL,
    expires timestamptz NOT NULL DEFAULT (now() + interval '10 minutes')
);
CREATE INDEX auth_oidc_flows_expiry ON auth_oidc_flows(expires);

CREATE TABLE auth_rate_limits (
    key bytea PRIMARY KEY,
    attempts integer NOT NULL,
    expires timestamptz NOT NULL
);
CREATE INDEX auth_rate_limits_expiry ON auth_rate_limits(expires);

ALTER TABLE audit_events ADD COLUMN actor_user_id uuid;

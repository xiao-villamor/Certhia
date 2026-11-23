CREATE TABLE auth_workspace_oidc (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision uuid NOT NULL,
    settings jsonb NOT NULL,
    client_secret bytea NOT NULL
);

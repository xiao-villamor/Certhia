# Sign-in and workspace access

Certhia requires a signed-in user for the dashboard and its API. Use HTTPS for shared deployments. The standard Compose file publishes the dashboard at `http://localhost:3001` on loopback.

## Set up the first administrator

Choose either method before opening Certhia to users.

- **Browser setup.** Open the dashboard and enter a username and a password. A username can be an email address if you plan to link single sign-on accounts by email. Whoever opens the setup screen first creates the administrator, so finish setup before exposing Certhia to other people. To gate the screen, set a high-entropy code with `CERTHIA_SETUP_TOKEN` or `CERTHIA_SETUP_TOKEN_FILE`; the screen then asks for it. Configure the same code on all replicas behind a load balancer. The screen closes as soon as the first user exists. Choose the default scanners, then scan a public image or import a report. Administrators can change scanner defaults or configure an issue tracker later in **Workspace preferences**.
- **Environment setup.** Set `CERTHIA_ADMIN_EMAIL` and either `CERTHIA_ADMIN_PASSWORD` or `CERTHIA_ADMIN_PASSWORD_FILE` before starting Certhia. The server creates an account named **Administrator** only if the database has no users. Remove the bootstrap variables and any bootstrap secret mount after the account is created. Changing a bootstrap credential after installation has no effect on the account.

Passwords need at least 8 characters and can be up to 1024 bytes. Certhia rejects a short list of common passwords and stores a salted Argon2id hash using 19 MiB of memory, two iterations, and one lane. [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## Roles and session management

| Role | Workspace access |
| --- | --- |
| Viewer | Read scan reports, findings, image and patch evidence, schedules, and comparisons. |
| Operator | Viewer access plus queue, import, rescan and cancel scans, triage findings, link issues, manage schedules and watches, use saved registry connections, and build or publish images. |
| Admin | Operator access plus manage users, workspace single sign-on, registry settings and webhook tokens, scanner and workspace preferences, activity history, and report deletion. |

Admins manage accounts in **Workspace preferences → Users**. Create a local account with an initial password and share it through a secure channel. For SSO, create an account without a password when email linking is enabled, or let the identity provider provision it. The Users section can edit roles, disable accounts, revoke sessions, and reset another local user’s password. Password recovery runs through an administrator or the server console. Keep at least one enabled administrator.

Sessions expire after 30 minutes without authenticated API activity or 12 hours from sign-in. Password and role changes, account disablement, and explicit revocation end the user's sessions. Users with local passwords can change them in **Your account**. Signing out ends the current Certhia session. Your identity provider manages its own session and MFA policy. Provisioned IdP users and local users share the same stable user IDs for authorization and audit. Future scoped tokens can reference those IDs independently of browser sessions and OIDC identities.

## Configure HTTPS and the reverse proxy

Publish only the TLS proxy. Forward the original `Host` authority, including any non-default port. The proxy should set its access logs to omit OIDC callback query strings, which carry short-lived OAuth codes. Use the same auth settings on every replica.

```dotenv
CERTHIA_ALLOWED_HOSTS=certhia.example.com,127.0.0.1
CERTHIA_AUTH_ORIGIN=https://certhia.example.com
CERTHIA_AUTH_SECURE_COOKIE=1
```

`CERTHIA_ALLOWED_HOSTS` contains bare hostnames or IP literals. Keep `127.0.0.1` if using the image's built-in Docker health check. Kubernetes health probes can supply an allowed internal `Host`. A configured origin includes the scheme and any non-default port, with no path. All browser mutations require an exact `Origin` that matches the request authority and, when set, the configured origin.

The server defaults to `CERTHIA_AUTH_SECURE_COOKIE=1`. Compose selects `0` for its default loopback HTTP setup. Only use `0` with loopback hostnames and an HTTP listener that is private to the local machine. With secure cookies, Certhia sets `__Host-certhia_session`. Cookies are HttpOnly, SameSite=Lax, and host-only.

Set `CERTHIA_AUTH_SECURE_COOKIE=auto` when the same instance is reached over HTTPS and over plain HTTP on a trusted network, for example a TLS hostname plus a LAN or VPN address. Sign-in then works on both, the `Origin` check accepts either scheme for the requested host, and the session cookie `certhia_session` omits the Secure attribute. Anyone who can watch the plain-HTTP traffic can read that cookie, so use `auto` only on networks you trust.

Login attempts are limited across replicas to 10 per account and 50 per client IP per five-minute window. By default, Certhia uses the TCP peer address. Behind a proxy, that can put everyone in one rate-limit bucket. To use the actual client IP, set `CERTHIA_AUTH_TRUSTED_PROXIES` to a comma-separated list of the **immediate** proxy IP addresses. Configure those proxies to overwrite `X-Real-IP` with the validated client address and restrict direct access to Certhia. Certhia ignores the header from other peers.

## Configure an OpenID Connect provider

### Configure company sign-in in the dashboard

1. Set up the public HTTPS origin as described above and sign in as a workspace administrator. Open **Workspace preferences → Single sign-on**.
2. Register the displayed **Redirect URI** for a confidential web client at your identity provider. Enable the authorization code flow with S256 PKCE.
3. Enter the issuer URL, client ID, client secret and allowed work email domains. For Microsoft Entra ID, register a single-tenant **Web** application, use the issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, include the email claim in ID tokens, and select **Send the client secret in the token request body**. Use tenant application assignment to restrict access. [Microsoft Entra OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
4. Save and test the new sign-in button in a separate browser session. You can invite passwordless accounts by work email in **Users**, or allow first-time users from the allowed domains to join as viewers. Change their roles in **Users**. Workspace-configured OIDC links by email only to accounts without a local password. If your provider omits email verification, enable that option only for a directory that controls and verifies the asserted email. Disabling the provider blocks new OIDC sign-ins. Use **Revoke sessions** in Users to end existing sessions.

The dashboard manages one company provider alongside deployment-managed providers. The client secret is encrypted with Certhia’s deployment key and is never returned by the settings API. Replicas reading the same database must use the same key. Enter a new secret when changing the issuer or client ID. Saving through the dashboard leaves the server’s password sign-in policy in effect.

### Configure providers through deployment settings

1. Register a confidential web client at the identity provider. Enable Authorization Code with S256 PKCE. Add the exact redirect URI `https://certhia.example.com/api/auth/oidc/<id>/callback`.
2. Set `CERTHIA_AUTH_ORIGIN` to that dashboard origin and add its hostname to `CERTHIA_ALLOWED_HOSTS`. Set up HTTPS as above.
3. Set `CERTHIA_OIDC_PROVIDERS` to a JSON array, or set `CERTHIA_OIDC_PROVIDERS_FILE` to a mounted JSON file path. Set one client secret per provider in the named environment variable or its `_FILE` counterpart. With Compose, mount files at the paths you configure. Add custom secret variable names to the app's `environment` in a Compose override.
4. Restart Certhia. Each provider shows a **Sign in with** button. Keep local login enabled until an administrator has tested OIDC sign-in.

Example provider file:

```json
[
  {
    "id": "work",
    "name": "Work account",
    "issuer": "https://sso.example.com/realms/work",
    "clientId": "certhia",
    "linkByEmail": true,
    "jit": true,
    "allowedDomains": ["example.com"],
    "roleClaim": "groups",
    "roleMap": { "/certhia-admins": "admin", "/certhia-operators": "operator" },
    "defaultRole": "viewer"
  }
]
```

Set `CERTHIA_OIDC_WORK_CLIENT_SECRET` or `CERTHIA_OIDC_WORK_CLIENT_SECRET_FILE` for this example.

A Compose override can mount both files with Compose secrets. This example pairs with the `work` provider above.

```yaml
services:
  app:
    environment:
      CERTHIA_OIDC_PROVIDERS_FILE: /run/secrets/certhia_oidc
      CERTHIA_OIDC_WORK_CLIENT_SECRET_FILE: /run/secrets/certhia_oidc_work
    secrets:
      - certhia_oidc
      - certhia_oidc_work
secrets:
  certhia_oidc:
    file: ./oidc-providers.json
  certhia_oidc_work:
    file: ./oidc-work.secret
```

Keep secret files outside version control and readable by the app container's UID 10001.

| Provider key | Behavior |
| --- | --- |
| `id`, `name`, `issuer`, `clientId` | Required. IDs use lowercase letters, digits, or dashes. Use the exact HTTPS issuer from discovery. Each provider must have a distinct issuer. |
| `clientSecretEnv` | Optional secret variable name. Defaults to `CERTHIA_OIDC_<ID>_CLIENT_SECRET` using uppercase and replacing dashes with underscores. Use that variable or add the suffix `_FILE` to supply a file path. |
| `secretPost` | Defaults to `false` for `client_secret_basic`. Set to `true` to send the secret in the token endpoint form using `client_secret_post`. |
| `linkByEmail` | Defaults to `false`. Allows an eligible IdP account to link to an existing user with the same normalized email and inherit that user's workspace role. |
| `trustEmail` | Defaults to `false`. Set only for an issuer that controls and verifies the directory email. Lets Certhia accept a missing `email_verified` claim. An explicit `false` is always rejected for email linking or provisioning. |
| `jit`, `allowedDomains` | `jit` defaults to `false`. When enabled, an eligible user with a new email can create an account on sign-in. JIT requires an exact email-domain allowlist. When supplied, the list also restricts email linking. |
| `requiredClaims` | Optional object of extra ID token claim names and exact string values required on every sign-in, including for already-linked identities. |
| `roleClaim`, `roleMap`, `defaultRole` | Apply when provisioning a new account. Map values from a top-level signed ID token claim, which can be a string or a string array. The highest matching role wins. The default is `viewer`. |
| `scopes` | Add scopes beyond `openid email profile` if the provider requires them for the configured claims. |

After initial linking, Certhia identifies the account by the issuer and subject. If an issuer supplies a different subject with the same email after an identity is already linked to that issuer, sign-in is denied. Claims used for first-time linking and provisioning must come from the ID token. Admins manage the ongoing workspace role in Certhia. If a user loses an IdP group or is deprovisioned, change or disable the Certhia account in **Users** to revoke any existing Certhia sessions. Browser sign-in does not retain IdP access or refresh tokens.

### Microsoft Entra ID

Use a **single-tenant** app registration with a **Web** redirect URI ending in `/entra/callback`. Add a client secret and configure the ID token to include an email for assigned users. App role values are available in the `roles` claim. Use assignment requirements on the enterprise application to limit who can sign in. Enable the trust override only for a managed tenant whose administrators control the asserted email. [Entra OpenID Connect](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) · [App roles](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)

```json
{
  "id": "entra",
  "name": "Microsoft Entra ID",
  "issuer": "https://login.microsoftonline.com/TENANT-ID/v2.0",
  "clientId": "APPLICATION-CLIENT-ID",
  "secretPost": true,
  "linkByEmail": true,
  "trustEmail": true,
  "allowedDomains": ["example.com"],
  "jit": true,
  "roleClaim": "roles",
  "roleMap": { "Certhia.Operator": "operator", "Certhia.Admin": "admin" }
}
```

### Okta

Create an **OIDC Web Application**, add the redirect URI ending in `/okta/callback`, and assign the app to the intended users or groups. This example uses an Okta custom authorization server. Configure a filtered `groups` claim included in the ID token, and configure the server's access policy for this client. For the org authorization server, use the plain Okta hostname as issuer and follow its ID token groups configuration. [Okta authorization servers](https://developer.okta.com/docs/concepts/auth-servers/) · [Okta groups claims](https://developer.okta.com/docs/guides/customize-tokens-groups-claim/)

```json
{
  "id": "okta",
  "name": "Okta",
  "issuer": "https://your-org.okta.com/oauth2/default",
  "clientId": "OKTA-CLIENT-ID",
  "linkByEmail": true,
  "allowedDomains": ["example.com"],
  "jit": true,
  "roleClaim": "groups",
  "roleMap": { "certhia-operators": "operator" }
}
```

### Google Workspace

Create an OAuth **Web application** client with the redirect URI ending in `/google/callback`. Configure the OAuth audience for your organization. Require the signed hosted-domain claim `hd` to confirm Workspace membership. New accounts receive the viewer role by default. [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect) · [Google ID token claims](https://developers.google.com/identity/openid-connect/reference)

```json
{
  "id": "google",
  "name": "Google Workspace",
  "issuer": "https://accounts.google.com",
  "clientId": "YOUR-CLIENT-ID.apps.googleusercontent.com",
  "secretPost": true,
  "linkByEmail": true,
  "allowedDomains": ["example.com"],
  "requiredClaims": { "hd": "example.com" },
  "jit": true
}
```

### Keycloak

Create an OpenID Connect client in your realm. Enable **Client authentication** and **Standard flow**. Set the valid redirect URI ending in `/keycloak/callback` and configure S256 PKCE for the client. Use the client secret from the Credentials tab. Require email verification and ensure the signed ID token includes the verification claim. Create a group membership mapper that emits `groups` as a string array in the ID token. This example uses full group paths. [Keycloak OpenID Connect guide](https://www.keycloak.org/securing-apps/oidc-layers) · [Keycloak server administration](https://www.keycloak.org/docs/latest/server_admin/)

```json
{
  "id": "keycloak",
  "name": "Keycloak",
  "issuer": "https://sso.example.com/realms/work",
  "clientId": "certhia",
  "linkByEmail": true,
  "allowedDomains": ["example.com"],
  "jit": true,
  "roleClaim": "groups",
  "roleMap": { "/certhia-operators": "operator", "/certhia-admins": "admin" }
}
```

For each example, wrap the provider object in an array or add it to an existing array. Set the secret using the provider's ID, such as `CERTHIA_OIDC_ENTRA_CLIENT_SECRET_FILE`.

## Disable local sign-in and recover access

After verifying a deployment-managed provider as an administrator, you can set `CERTHIA_AUTH_LOCAL=0` and restart. Keep a separate enabled local administrator with a strong password in your emergency credential vault. Use an address that is outside all provider email-linking policies. Local password hashes are retained when local login is disabled. If the identity provider goes down, set `CERTHIA_AUTH_LOCAL=1`, restart, and use the emergency account. If a provider configuration prevents startup, remove the provider settings during recovery.

For a forgotten local admin password, run the server binary with the `reset-admin-password` command, the deployment's database connection settings, `CERTHIA_ADMIN_EMAIL`, and a new `CERTHIA_ADMIN_PASSWORD_FILE` mounted from your emergency secret store. Set `CERTHIA_AUTH_LOCAL=1` and clear broken OIDC configuration if needed. In a Compose deployment, you can run the command with `docker compose run --rm --no-deps app reset-admin-password` when the environment and secret mount are configured for that invocation. The command updates an enabled administrator, revokes that user's sessions, logs the recovery event, and exits without listening for requests. Remove the recovery secret and restore your intended deployment settings afterward.

## API clients and audit

`/api/health`, `/api/ready`, and `/api/version` remain public. Registry webhook delivery uses registry webhook tokens. Dashboard API clients use a session cookie with the exact dashboard `Origin` for mutations. The API returns JSON `401` for absent or expired sessions and `403` when a role lacks permission. Use the registry webhook for automated scan triggers.

**Activity history** includes authentication and account changes alongside the existing workspace events. The actor user ID is attached to work directly attributed to a signed-in request. Background jobs and machine-token requests have no browser user.

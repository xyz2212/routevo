# Security and identity provider

Routevo runs as both an OpenID Connect identity provider and an OAuth2 JWT
resource server. Browser account APIs use an HTTP session and a CSRF cookie;
the existing `/api/**` and `/graphql` resource APIs remain stateless and require
a JWT issued by this application with the `api.read` scope. Do not send a bearer
token to the browser account API.

Customer accounts can be registered through `POST /api/auth/register`. The
response does not reveal whether an address is already registered. Email
verification and password-reset links are random, one-hour, one-time tokens;
only SHA-256 token hashes are persisted. Unverified customers cannot sign in.
Login, current-profile, logout, CSRF, resend-verification, and password recovery
are available under `/api/auth`. Mutating requests require the CSRF token
returned by `GET /api/auth/csrf` in the response's indicated header, in
addition to the `XSRF-TOKEN` cookie.

Users, roles, action tokens, and request-rate buckets are stored in PostgreSQL.
Registration/recovery limits use database-backed rolling windows keyed by
hashed client IP and, where applicable, normalized email. `request.getRemoteAddr`
is used as the client IP; configure a trusted reverse proxy to provide a
correct remote address rather than trusting arbitrary forwarded headers.
The initial admin is seeded only when its normalized email is absent. Its
password is BCrypt-hashed and is not reset from the environment on subsequent
starts. OAuth client registrations are still held in memory and recreated at
startup; they are not yet database-backed.

Driver onboarding, admin MFA, and customer/driver/admin onboarding screens are
not implemented yet. Do not treat this identity slice as launch-ready for
driver or administrator operations.

The account UI is a React application served from `/app/`. Build it before
packaging the Spring application:

```sh
npm ci
npm run build:web
./gradlew bootJar
```

## Required deployment settings

Supply these settings through the process environment or another protected
configuration source:

| Environment variable | Purpose |
| --- | --- |
| `IDENTITY_ISSUER_URI` | Canonical externally reachable issuer URL, such as `https://auth.example.com`. |
| `IDENTITY_ADMIN_EMAIL` | Email address for the initial administrator account. |
| `IDENTITY_ADMIN_NAME` | Display name for the initial administrator account. |
| `IDENTITY_ADMIN_PASSWORD` | Password for the initial administrator account. |
| `IDENTITY_EMAIL_FROM` | Verified sender address for account lifecycle messages. |
| `FRONTEND_BASE_URL` | HTTPS frontend base URL used to construct verification and password-reset links. |
| `SMTP_HOST`, `SMTP_PORT` | SMTP server used for account email. |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | Optional SMTP credentials. |
| `SMTP_AUTH`, `SMTP_STARTTLS` | SMTP authentication and STARTTLS configuration. |
| `IDENTITY_COOKIE_SECURE` | Keep `true` in deployed environments; set `false` only for local HTTP development. |
| `IDENTITY_RATE_LIMIT_PER_IP` | Maximum requests per IP and action in the configured window (default `30`). |
| `IDENTITY_RATE_LIMIT_PER_IDENTITY` | Maximum requests per normalized email and action (default `10`). |
| `IDENTITY_RATE_LIMIT_WINDOW` | ISO-8601 rate-limit window (default `PT15M`). |
| `IDENTITY_CLIENT_ID` | OAuth client identifier. |
| `IDENTITY_CLIENT_SECRET` | OAuth client secret. |
| `IDENTITY_CLIENT_REDIRECT_URI` | Exact callback URL registered for the client. |
| `IDENTITY_SIGNING_KEY_STORE` | Path to a PKCS#12 keystore mounted outside the repository. |
| `IDENTITY_SIGNING_KEY_STORE_PASSWORD` | Keystore password. |
| `IDENTITY_SIGNING_KEY_ALIAS` | Alias of the RSA signing key and certificate. |

Use long, unique secrets and keep the keystore and secret values out of source
control. The same password protects the PKCS#12 file and its private key entry.
The issuer URL must exactly match the URL clients use to reach this service;
changing it invalidates issuer checks for already-issued tokens.
Keep session cookies `HttpOnly`, `Secure`, and `SameSite=Lax` in production and
serve the application over HTTPS. Store SMTP credentials in a protected
configuration source. Email delivery runs after the account transaction so
SMTP outages do not make registration responses reveal whether an address is
registered. Delivery failures are logged; users can request a resend after
SMTP is restored. Configure and test SMTP before exposing registration or
recovery.

Create an RSA PKCS#12 signing keystore outside the repository, for example:

```sh
keytool -genkeypair -alias routevo-signing -keyalg RSA -keysize 3072 \
  -storetype PKCS12 -keystore /secure/path/routevo-identity.p12
```

Set `IDENTITY_SIGNING_KEY_ALIAS` to the alias used in that command.

The configured OAuth client uses authorization code and refresh-token grants,
requires PKCE and user consent, and receives `openid` and `api.read` scopes.
Use HTTPS in deployed environments.

# Routevo

Routevo is a Hong Kong local-delivery marketplace backend built with Spring
Boot, PostgreSQL, and a React account interface.

## Development

1. Provide the required identity, database, mail, and OAuth settings described
   in [Security and identity provider](./docs/security.md).
2. Install frontend dependencies with `npm ci`.
3. Build the React account interface with `npm run build:web`.
4. Run backend checks with `./gradlew test`.
5. Start the development services with `docker compose up -d`, then run
   `npm run dev`.

The current UI supports account registration, email verification, sign-in,
password recovery, administrator invitations and TOTP MFA, and metadata-only
driver applications/review. Driver activation and delivery operations are not enabled.
Read the [onboarding guide](./docs/onboarding.md) for the current status of
customer, driver, and administrator paths.
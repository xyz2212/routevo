# Routevo onboarding

## Customer

1. Create an account with an email address you control and a password of at
   least 12 characters.
2. Open the verification link delivered to that address. Unverified accounts
   cannot sign in.
3. Sign in at `/app/`. Use password recovery if you lose access; a password
   reset invalidates existing browser sessions.
4. Delivery booking is not enabled yet. Do not send payment details, pickup
   codes, or delivery information to Routevo until booking is available.

## Driver

1. Register and verify a customer account, then sign in at `/app/`.
2. Apply with your vehicle type and Hong Kong service area. Your account name,
   email, and optional phone number are shared with administrators reviewing
   the application.
3. If an administrator requests more information, update the vehicle type or
   service area in the application panel.
4. An approval is provisional: it does not grant driver access or enable
   deliveries. Private document storage, compliance requirements, and
   operational controls must be configured before driver activation.

Do not submit identity, licence, vehicle-registration, or insurance documents
through this site or by email. The application currently collects metadata
only.

## Administrator

The initial administrator account is provisioned from protected deployment
configuration. On first sign-in, enroll an authenticator app and save the
one-time recovery codes in a private location. Administrators can invite
additional administrators by email; invitees choose a password and must enroll
MFA before receiving admin access. Driver applications can be reviewed from
the onboarding panel; review decisions do not activate driver accounts. Do not
share administrator credentials or use them for day-to-day customer activity.
Delivery booking and live operations remain disabled.

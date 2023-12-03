# Request
curl --location 'http://localhost:8080/admin/realms/fkh-customers-sample/authentication/authenticator-providers' \
--header 'Authorization: Bearer {{ access_token }}'


# Response
[
    {
        "displayName": "Cookie",
        "description": "Validates the SSO cookie set by the auth server.",
        "id": "auth-cookie"
    },
    {
        "displayName": "Choose User",
        "description": "Choose a user to reset credentials for",
        "id": "reset-credentials-choose-user"
    },
    {
        "displayName": "WebAuthn Authenticator",
        "description": "Authenticator for WebAuthn. Usually used for WebAuthn two-factor authentication",
        "id": "webauthn-authenticator"
    },
    {
        "displayName": "Password",
        "description": "Validates the password supplied as a 'password' form parameter in direct grant request",
        "id": "direct-grant-validate-password"
    },
    {
        "displayName": "Kerberos",
        "description": "Initiates the SPNEGO protocol.  Most often used with Kerberos.",
        "id": "auth-spnego"
    },
    {
        "displayName": "Reset Password",
        "description": "Sets the Update Password required action if execution is REQUIRED.  Will also set it if execution is OPTIONAL and the password is currently configured for it.",
        "id": "reset-password"
    },
    {
        "displayName": "X509/Validate Username",
        "description": "Validates username and password from X509 client certificate received as a part of mutual SSL handshake.",
        "id": "direct-grant-auth-x509-username"
    },
    {
        "displayName": "Password Form",
        "description": "Validates a password from login form.",
        "id": "auth-password-form"
    },
    {
        "displayName": "Docker Authenticator",
        "description": "Uses HTTP Basic authentication to validate docker users, returning a docker error token on auth failure",
        "id": "docker-http-basic-authenticator"
    },
    {
        "displayName": "Username Password Form for identity provider reauthentication",
        "description": "Validates a password from login form. Username may be already known from identity provider authentication",
        "id": "idp-username-password-form"
    },
    {
        "displayName": "Allow access",
        "description": "Authenticator will always successfully authenticate. Useful for example in the conditional flows to be used after satisfying the previous conditions",
        "id": "allow-access-authenticator"
    },
    {
        "displayName": "Verify existing account by Email",
        "description": "Email verification of existing Keycloak user, that wants to link his user account with identity provider",
        "id": "idp-email-verification"
    },
    {
        "displayName": "Automatically set existing user",
        "description": "Automatically set existing user to authentication context without any verification",
        "id": "idp-auto-link"
    },
    {
        "displayName": "X509/Validate Username Form",
        "description": "Validates username and password from X509 client certificate received as a part of mutual SSL handshake.",
        "id": "auth-x509-client-username-form"
    },
    {
        "displayName": "Condition - user role",
        "description": "Flow is executed only if user has the given role.",
        "id": "conditional-user-role"
    },
    {
        "displayName": "Deny access",
        "description": "Access will be always denied. Useful for example in the conditional flows to be used after satisfying the previous conditions",
        "id": "deny-access-authenticator"
    },
    {
        "displayName": "Identity Provider Redirector",
        "description": "Redirects to default Identity Provider or Identity Provider specified with kc_idp_hint query parameter",
        "id": "identity-provider-redirector"
    },
    {
        "displayName": "Reset OTP",
        "description": "Removes existing OTP configurations (if chosen) and sets the 'Configure OTP' required action.",
        "id": "reset-otp"
    },
    {
        "displayName": "Username Validation",
        "description": "Validates the username supplied as a 'username' form parameter in direct grant request",
        "id": "direct-grant-validate-username"
    },
    {
        "displayName": "Condition - user configured",
        "description": "Executes the current flow only if authenticators are configured",
        "id": "conditional-user-configured"
    },
    {
        "displayName": "WebAuthn Passwordless Authenticator",
        "description": "Authenticator for Passwordless WebAuthn authentication",
        "id": "webauthn-authenticator-passwordless"
    },
    {
        "displayName": "Review Profile",
        "description": "User reviews and updates profile data retrieved from Identity Provider in the displayed form",
        "id": "idp-review-profile"
    },
    {
        "displayName": "Conditional OTP Form",
        "description": "Validates a OTP on a separate OTP form. Only shown if required based on the configured conditions.",
        "id": "auth-conditional-otp-form"
    },
    {
        "displayName": "Confirm link existing account",
        "description": "Show the form where user confirms if he wants to link identity provider with existing account or rather edit user profile data retrieved from identity provider to avoid conflict",
        "id": "idp-confirm-link"
    },
    {
        "displayName": "Username Password Form",
        "description": "Validates a username and password from login form.",
        "id": "auth-username-password-form"
    },
    {
        "displayName": "User session count limiter",
        "description": "Configures how many concurrent sessions a single user is allowed to create for this realm and/or client",
        "id": "user-session-limits"
    },
    {
        "displayName": "Send Reset Email",
        "description": "Send email to user and wait for response.",
        "id": "reset-credential-email"
    },
    {
        "displayName": "Condition - user attribute",
        "description": "Flow is executed only if the user attribute exists and has the expected value",
        "id": "conditional-user-attribute"
    },
    {
        "displayName": "Username Form",
        "description": "Selects a user from his username.",
        "id": "auth-username-form"
    },
    {
        "displayName": "Detect existing broker user",
        "description": "Detect if there is an existing Keycloak account with same email like identity provider. If no, throw an error.",
        "id": "idp-detect-existing-broker-user"
    },
    {
        "displayName": "HTTP Basic Authentication",
        "description": "Validates username and password from Authorization HTTP header",
        "id": "http-basic-authenticator"
    },
    {
        "displayName": "Condition - Level of Authentication",
        "description": "Flow is executed only if the configured LOA or a higher one has been requested but not yet satisfied. After the flow is successfully finished, the LOA in the session will be updated to value prescribed by this condition.",
        "id": "conditional-level-of-authentication"
    },
    {
        "displayName": "OTP Form",
        "description": "Validates a OTP on a separate OTP form.",
        "id": "auth-otp-form"
    },
    {
        "displayName": "OTP",
        "description": "Validates the one time password supplied as a 'totp' form parameter in direct grant request",
        "id": "direct-grant-validate-otp"
    },
    {
        "displayName": "Create User If Unique",
        "description": "Detect if there is existing Keycloak account with same email like identity provider. If no, create new user",
        "id": "idp-create-user-if-unique"
    }
]


# DB Queries
docker-postgres-1  | 2023-12-03 10:09:43.141 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 10:09:43.141 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 10:09:43.141 UTC [219] DETAIL:  parameters: $1 = 'manage-realm', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 10:09:43.149 UTC [219] LOG:  execute S_1: COMMIT



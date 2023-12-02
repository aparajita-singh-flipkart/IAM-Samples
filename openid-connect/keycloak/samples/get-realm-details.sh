# Request:
curl --location 'http://localhost:8080/admin/realms/master' \
--header 'Authorization: Bearer {{ access_token }}'


# Response:
{
    "id": "d87b5dc5-5fc7-4a96-bcd9-0f99800c8195",
    "realm": "master",
    "displayName": "Keycloak",
    "displayNameHtml": "<div class=\"kc-logo-text\"><span>Keycloak</span></div>",
    "notBefore": 0,
    "defaultSignatureAlgorithm": "RS256",
    "revokeRefreshToken": false,
    "refreshTokenMaxReuse": 0,
    "accessTokenLifespan": 60,
    "accessTokenLifespanForImplicitFlow": 900,
    "ssoSessionIdleTimeout": 1800,
    "ssoSessionMaxLifespan": 36000,
    "ssoSessionIdleTimeoutRememberMe": 0,
    "ssoSessionMaxLifespanRememberMe": 0,
    "offlineSessionIdleTimeout": 2592000,
    "offlineSessionMaxLifespanEnabled": false,
    "offlineSessionMaxLifespan": 5184000,
    "clientSessionIdleTimeout": 0,
    "clientSessionMaxLifespan": 0,
    "clientOfflineSessionIdleTimeout": 0,
    "clientOfflineSessionMaxLifespan": 0,
    "accessCodeLifespan": 60,
    "accessCodeLifespanUserAction": 300,
    "accessCodeLifespanLogin": 1800,
    "actionTokenGeneratedByAdminLifespan": 43200,
    "actionTokenGeneratedByUserLifespan": 300,
    "oauth2DeviceCodeLifespan": 600,
    "oauth2DevicePollingInterval": 5,
    "enabled": true,
    "sslRequired": "external",
    "registrationAllowed": false,
    "registrationEmailAsUsername": false,
    "rememberMe": false,
    "verifyEmail": false,
    "loginWithEmailAllowed": true,
    "duplicateEmailsAllowed": false,
    "resetPasswordAllowed": false,
    "editUsernameAllowed": false,
    "bruteForceProtected": false,
    "permanentLockout": false,
    "maxFailureWaitSeconds": 900,
    "minimumQuickLoginWaitSeconds": 60,
    "waitIncrementSeconds": 60,
    "quickLoginCheckMilliSeconds": 1000,
    "maxDeltaTimeSeconds": 43200,
    "failureFactor": 30,
    "defaultRole": {
        "id": "2cb1616a-f451-4d0c-9a57-83d46e3f7dce",
        "name": "default-roles-master",
        "description": "${role_default-roles}",
        "composite": true,
        "clientRole": false,
        "containerId": "d87b5dc5-5fc7-4a96-bcd9-0f99800c8195"
    },
    "requiredCredentials": [
        "password"
    ],
    "otpPolicyType": "totp",
    "otpPolicyAlgorithm": "HmacSHA1",
    "otpPolicyInitialCounter": 0,
    "otpPolicyDigits": 6,
    "otpPolicyLookAheadWindow": 1,
    "otpPolicyPeriod": 30,
    "otpPolicyCodeReusable": false,
    "otpSupportedApplications": [
        "totpAppMicrosoftAuthenticatorName",
        "totpAppGoogleName",
        "totpAppFreeOTPName"
    ],
    "webAuthnPolicyRpEntityName": "keycloak",
    "webAuthnPolicySignatureAlgorithms": [
        "ES256"
    ],
    "webAuthnPolicyRpId": "",
    "webAuthnPolicyAttestationConveyancePreference": "not specified",
    "webAuthnPolicyAuthenticatorAttachment": "not specified",
    "webAuthnPolicyRequireResidentKey": "not specified",
    "webAuthnPolicyUserVerificationRequirement": "not specified",
    "webAuthnPolicyCreateTimeout": 0,
    "webAuthnPolicyAvoidSameAuthenticatorRegister": false,
    "webAuthnPolicyAcceptableAaguids": [],
    "webAuthnPolicyPasswordlessRpEntityName": "keycloak",
    "webAuthnPolicyPasswordlessSignatureAlgorithms": [
        "ES256"
    ],
    "webAuthnPolicyPasswordlessRpId": "",
    "webAuthnPolicyPasswordlessAttestationConveyancePreference": "not specified",
    "webAuthnPolicyPasswordlessAuthenticatorAttachment": "not specified",
    "webAuthnPolicyPasswordlessRequireResidentKey": "not specified",
    "webAuthnPolicyPasswordlessUserVerificationRequirement": "not specified",
    "webAuthnPolicyPasswordlessCreateTimeout": 0,
    "webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister": false,
    "webAuthnPolicyPasswordlessAcceptableAaguids": [],
    "browserSecurityHeaders": {
        "contentSecurityPolicyReportOnly": "",
        "xContentTypeOptions": "nosniff",
        "referrerPolicy": "no-referrer",
        "xRobotsTag": "none",
        "xFrameOptions": "SAMEORIGIN",
        "xXSSProtection": "1; mode=block",
        "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
        "strictTransportSecurity": "max-age=31536000; includeSubDomains"
    },
    "smtpServer": {},
    "eventsEnabled": false,
    "eventsListeners": [
        "jboss-logging"
    ],
    "enabledEventTypes": [],
    "adminEventsEnabled": false,
    "adminEventsDetailsEnabled": false,
    "identityProviders": [],
    "identityProviderMappers": [],
    "internationalizationEnabled": false,
    "supportedLocales": [],
    "browserFlow": "browser",
    "registrationFlow": "registration",
    "directGrantFlow": "direct grant",
    "resetCredentialsFlow": "reset credentials",
    "clientAuthenticationFlow": "clients",
    "dockerAuthenticationFlow": "docker auth",
    "attributes": {
        "cibaBackchannelTokenDeliveryMode": "poll",
        "cibaExpiresIn": "120",
        "cibaAuthRequestedUserHint": "login_hint",
        "parRequestUriLifespan": "60",
        "cibaInterval": "5",
        "realmReusableOtpCode": "false"
    },
    "userManagedAccessAllowed": false,
    "clientProfiles": {
        "profiles": []
    },
    "clientPolicies": {
        "policies": []
    }
}


# DB Queries

docker-postgres-1  | 2023-12-02 20:33:55.787 UTC [30] LOG:  execute <unnamed>: BEGIN
docker-postgres-1  | 2023-12-02 20:33:55.787 UTC [30] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-02 20:33:55.787 UTC [30] DETAIL:  parameters: $1 = 'master-realm', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-02 20:33:55.798 UTC [30] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-02 20:33:55.798 UTC [30] DETAIL:  parameters: $1 = 'manage-realm', $2 = '14219729-0aa9-47b9-9f8d-cc0a7418250b'
docker-postgres-1  | 2023-12-02 20:33:55.830 UTC [30] LOG:  execute <unnamed>: select r1_0.ID,r1_0.ACCESS_CODE_LIFESPAN,r1_0.LOGIN_LIFESPAN,r1_0.USER_ACTION_LIFESPAN,r1_0.ACCESS_TOKEN_LIFESPAN,r1_0.ACCESS_TOKEN_LIFE_IMPLICIT,r1_0.ACCOUNT_THEME,r1_0.ADMIN_EVENTS_DETAILS_ENABLED,r1_0.ADMIN_EVENTS_ENABLED,r1_0.ADMIN_THEME,r1_0.ALLOW_USER_MANAGED_ACCESS,r1_0.BROWSER_FLOW,r1_0.CLIENT_AUTH_FLOW,r1_0.DEFAULT_LOCALE,r1_0.DEFAULT_ROLE,r1_0.DIRECT_GRANT_FLOW,r1_0.DOCKER_AUTH_FLOW,r1_0.DUPLICATE_EMAILS_ALLOWED,r1_0.EDIT_USERNAME_ALLOWED,r1_0.EMAIL_THEME,r1_0.ENABLED,r1_0.EVENTS_ENABLED,r1_0.EVENTS_EXPIRATION,r1_0.INTERNATIONALIZATION_ENABLED,r1_0.LOGIN_THEME,r1_0.LOGIN_WITH_EMAIL_ALLOWED,r1_0.MASTER_ADMIN_CLIENT,r1_0.NAME,r1_0.NOT_BEFORE,r1_0.OFFLINE_SESSION_IDLE_TIMEOUT,r1_0.OTP_POLICY_ALG,r1_0.OTP_POLICY_DIGITS,r1_0.OTP_POLICY_COUNTER,r1_0.OTP_POLICY_WINDOW,r1_0.OTP_POLICY_PERIOD,r1_0.OTP_POLICY_TYPE,r1_0.PASSWORD_POLICY,r1_0.REFRESH_TOKEN_MAX_REUSE,r1_0.REGISTRATION_ALLOWED,r1_0.REG_EMAIL_AS_USERNAME,r1_0.REGISTRATION_FLOW,r1_0.REMEMBER_ME,r1_0.RESET_CREDENTIALS_FLOW,r1_0.RESET_PASSWORD_ALLOWED,r1_0.REVOKE_REFRESH_TOKEN,r1_0.SSL_REQUIRED,r1_0.SSO_IDLE_TIMEOUT,r1_0.SSO_IDLE_TIMEOUT_REMEMBER_ME,r1_0.SSO_MAX_LIFESPAN,r1_0.SSO_MAX_LIFESPAN_REMEMBER_ME,r1_0.VERIFY_EMAIL,a1_0.REALM_ID,a1_0.NAME,a1_0.VALUE from REALM r1_0 left join REALM_ATTRIBUTE a1_0 on r1_0.ID=a1_0.REALM_ID where r1_0.ID=$1
docker-postgres-1  | 2023-12-02 20:33:55.830 UTC [30] DETAIL:  parameters: $1 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-02 20:33:55.917 UTC [30] LOG:  execute S_2: COMMIT



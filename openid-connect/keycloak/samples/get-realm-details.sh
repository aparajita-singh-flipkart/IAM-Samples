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

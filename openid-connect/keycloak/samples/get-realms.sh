# Request
curl --location 'http://localhost:8080/admin/realms' \
--header 'Authorization: Bearer {{ access_token }}'


# Response
[
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
    },
    {
        "id": "fkh-customers-sample",
        "realm": "fkh-customers-sample",
        "notBefore": 0,
        "defaultSignatureAlgorithm": "RS256",
        "revokeRefreshToken": false,
        "refreshTokenMaxReuse": 0,
        "accessTokenLifespan": 300,
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
            "id": "12c4f394-a345-495a-be74-776f00efc836",
            "name": "default-roles-fkh-customers-sample",
            "description": "${role_default-roles}",
            "composite": true,
            "clientRole": false,
            "containerId": "fkh-customers-sample"
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
            "contentSecurityPolicy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
            "xXSSProtection": "1; mode=block",
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
        "identityProviders": [
            {
                "alias": "keycloak-oidc",
                "internalId": "d79d0d65-8ee1-47f0-8611-f9e6eea71f20",
                "providerId": "keycloak-oidc",
                "enabled": true,
                "updateProfileFirstLoginMode": "on",
                "trustEmail": false,
                "storeToken": false,
                "addReadTokenRoleOnCreate": false,
                "authenticateByDefault": false,
                "linkOnly": false,
                "firstBrokerLoginFlowAlias": "first broker login",
                "config": {
                    "clientId": "ssss",
                    "tokenUrl": "http://localhost",
                    "authorizationUrl": "http://localhost",
                    "clientAuthMethod": "client_secret_basic",
                    "syncMode": "IMPORT",
                    "clientSecret": "assaasa",
                    "useJwksUrl": "true"
                }
            },
            {
                "alias": "keycloak-oidc-2",
                "internalId": "7cf3fd74-8d3a-4c8d-b651-fcc885df8a31",
                "providerId": "keycloak-oidc",
                "enabled": true,
                "updateProfileFirstLoginMode": "on",
                "trustEmail": false,
                "storeToken": false,
                "addReadTokenRoleOnCreate": false,
                "authenticateByDefault": false,
                "linkOnly": false,
                "firstBrokerLoginFlowAlias": "first broker login",
                "config": {}
            }
        ],
        "identityProviderMappers": [
            {
                "id": "2168f3db-1c2f-4b5a-ba5c-9dd22ead2aa5",
                "name": "test-mapper",
                "identityProviderAlias": "keycloak-oidc2",
                "identityProviderMapper": "keycloak-oidc",
                "config": {}
            },
            {
                "id": "dd961620-6bbd-4b05-9594-e83522acfc7f",
                "name": "test",
                "identityProviderAlias": "keycloak-oidc-2",
                "identityProviderMapper": "hardcoded-user-session-attribute-idp-mapper",
                "config": {
                    "syncMode": "INHERIT"
                }
            }
        ],
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
            "oauth2DeviceCodeLifespan": "600",
            "oauth2DevicePollingInterval": "5",
            "clientSessionIdleTimeout": "0",
            "parRequestUriLifespan": "60",
            "clientSessionMaxLifespan": "0",
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
]


# DB Queries

docker-postgres-1  | 2023-12-03 09:31:40.963 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 09:31:40.965 UTC [219] LOG:  execute S_36: select r1_0.ID from REALM r1_0
docker-postgres-1  | 2023-12-03 09:31:40.968 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:31:40.968 UTC [219] DETAIL:  parameters: $1 = 'view-realm', $2 = '14219729-0aa9-47b9-9f8d-cc0a7418250b'
docker-postgres-1  | 2023-12-03 09:31:40.980 UTC [219] LOG:  execute <unnamed>: select r1_0.ID,r1_0.ACCESS_CODE_LIFESPAN,r1_0.LOGIN_LIFESPAN,r1_0.USER_ACTION_LIFESPAN,r1_0.ACCESS_TOKEN_LIFESPAN,r1_0.ACCESS_TOKEN_LIFE_IMPLICIT,r1_0.ACCOUNT_THEME,r1_0.ADMIN_EVENTS_DETAILS_ENABLED,r1_0.ADMIN_EVENTS_ENABLED,r1_0.ADMIN_THEME,r1_0.ALLOW_USER_MANAGED_ACCESS,r1_0.BROWSER_FLOW,r1_0.CLIENT_AUTH_FLOW,r1_0.DEFAULT_LOCALE,r1_0.DEFAULT_ROLE,r1_0.DIRECT_GRANT_FLOW,r1_0.DOCKER_AUTH_FLOW,r1_0.DUPLICATE_EMAILS_ALLOWED,r1_0.EDIT_USERNAME_ALLOWED,r1_0.EMAIL_THEME,r1_0.ENABLED,r1_0.EVENTS_ENABLED,r1_0.EVENTS_EXPIRATION,r1_0.INTERNATIONALIZATION_ENABLED,r1_0.LOGIN_THEME,r1_0.LOGIN_WITH_EMAIL_ALLOWED,r1_0.MASTER_ADMIN_CLIENT,r1_0.NAME,r1_0.NOT_BEFORE,r1_0.OFFLINE_SESSION_IDLE_TIMEOUT,r1_0.OTP_POLICY_ALG,r1_0.OTP_POLICY_DIGITS,r1_0.OTP_POLICY_COUNTER,r1_0.OTP_POLICY_WINDOW,r1_0.OTP_POLICY_PERIOD,r1_0.OTP_POLICY_TYPE,r1_0.PASSWORD_POLICY,r1_0.REFRESH_TOKEN_MAX_REUSE,r1_0.REGISTRATION_ALLOWED,r1_0.REG_EMAIL_AS_USERNAME,r1_0.REGISTRATION_FLOW,r1_0.REMEMBER_ME,r1_0.RESET_CREDENTIALS_FLOW,r1_0.RESET_PASSWORD_ALLOWED,r1_0.REVOKE_REFRESH_TOKEN,r1_0.SSL_REQUIRED,r1_0.SSO_IDLE_TIMEOUT,r1_0.SSO_IDLE_TIMEOUT_REMEMBER_ME,r1_0.SSO_MAX_LIFESPAN,r1_0.SSO_MAX_LIFESPAN_REMEMBER_ME,r1_0.VERIFY_EMAIL,a1_0.REALM_ID,a1_0.NAME,a1_0.VALUE from REALM r1_0 left join REALM_ATTRIBUTE a1_0 on r1_0.ID=a1_0.REALM_ID where r1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:40.980 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:40.993 UTC [219] LOG:  execute <unnamed>: select i1_0.REALM_ID,i1_0.INTERNAL_ID,i1_0.ADD_TOKEN_ROLE,i1_0.PROVIDER_ALIAS,i1_0.AUTHENTICATE_BY_DEFAULT,i1_0.PROVIDER_DISPLAY_NAME,i1_0.ENABLED,i1_0.FIRST_BROKER_LOGIN_FLOW_ID,i1_0.LINK_ONLY,i1_0.POST_BROKER_LOGIN_FLOW_ID,i1_0.PROVIDER_ID,i1_0.STORE_TOKEN,i1_0.TRUST_EMAIL from IDENTITY_PROVIDER i1_0 where i1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:40.993 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:40.996 UTC [219] LOG:  execute <unnamed>: select r1_0.REALM_ID,r1_0.TYPE,r1_0.FORM_LABEL,r1_0.INPUT,r1_0.SECRET from REALM_REQUIRED_CREDENTIAL r1_0 where r1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:40.996 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:40.999 UTC [219] LOG:  execute <unnamed>: select c1_0.IDENTITY_PROVIDER_ID,c1_0.NAME,c1_0.VALUE from IDENTITY_PROVIDER_CONFIG c1_0 where c1_0.IDENTITY_PROVIDER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:40.999 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20'
docker-postgres-1  | 2023-12-03 09:31:41.002 UTC [219] LOG:  execute <unnamed>: select c1_0.IDENTITY_PROVIDER_ID,c1_0.NAME,c1_0.VALUE from IDENTITY_PROVIDER_CONFIG c1_0 where c1_0.IDENTITY_PROVIDER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.002 UTC [219] DETAIL:  parameters: $1 = '7cf3fd74-8d3a-4c8d-b651-fcc885df8a31'
docker-postgres-1  | 2023-12-03 09:31:41.007 UTC [219] LOG:  execute <unnamed>: select i1_0.REALM_ID,i1_0.ID,i1_0.IDP_ALIAS,i1_0.IDP_MAPPER_NAME,i1_0.NAME from IDENTITY_PROVIDER_MAPPER i1_0 where i1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.007 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.010 UTC [219] LOG:  execute <unnamed>: select c1_0.IDP_MAPPER_ID,c1_0.NAME,c1_0.VALUE from IDP_MAPPER_CONFIG c1_0 where c1_0.IDP_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.010 UTC [219] DETAIL:  parameters: $1 = '2168f3db-1c2f-4b5a-ba5c-9dd22ead2aa5'
docker-postgres-1  | 2023-12-03 09:31:41.013 UTC [219] LOG:  execute <unnamed>: select c1_0.IDP_MAPPER_ID,c1_0.NAME,c1_0.VALUE from IDP_MAPPER_CONFIG c1_0 where c1_0.IDP_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.013 UTC [219] DETAIL:  parameters: $1 = 'dd961620-6bbd-4b05-9594-e83522acfc7f'
docker-postgres-1  | 2023-12-03 09:31:41.016 UTC [219] LOG:  execute <unnamed>: select s1_0.REALM_ID,s1_0.NAME,s1_0.VALUE from REALM_SMTP_CONFIG s1_0 where s1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.016 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.020 UTC [219] LOG:  execute <unnamed>: select e1_0.REALM_ID,e1_0.VALUE from REALM_EVENTS_LISTENERS e1_0 where e1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.020 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.024 UTC [219] LOG:  execute <unnamed>: select e1_0.REALM_ID,e1_0.VALUE from REALM_ENABLED_EVENT_TYPES e1_0 where e1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.024 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.026 UTC [219] LOG:  execute S_37: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.026 UTC [219] DETAIL:  parameters: $1 = '12c4f394-a345-495a-be74-776f00efc836'
docker-postgres-1  | 2023-12-03 09:31:41.029 UTC [219] LOG:  execute S_32: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-03 09:31:41.029 UTC [219] DETAIL:  parameters: $1 = '12c4f394-a345-495a-be74-776f00efc836'
docker-postgres-1  | 2023-12-03 09:31:41.034 UTC [219] LOG:  execute <unnamed>: select c1_0.ID,c1_0.ALWAYS_DISPLAY_IN_CONSOLE,c1_0.BASE_URL,c1_0.BEARER_ONLY,c1_0.CLIENT_AUTHENTICATOR_TYPE,c1_0.CLIENT_ID,c1_0.CONSENT_REQUIRED,c1_0.DESCRIPTION,c1_0.DIRECT_ACCESS_GRANTS_ENABLED,c1_0.ENABLED,c1_0.FRONTCHANNEL_LOGOUT,c1_0.FULL_SCOPE_ALLOWED,c1_0.IMPLICIT_FLOW_ENABLED,c1_0.MANAGEMENT_URL,c1_0.NAME,c1_0.NODE_REREG_TIMEOUT,c1_0.NOT_BEFORE,c1_0.PROTOCOL,c1_0.PUBLIC_CLIENT,c1_0.REALM_ID,c1_0.REGISTRATION_TOKEN,c1_0.ROOT_URL,c1_0.SECRET,c1_0.SERVICE_ACCOUNTS_ENABLED,c1_0.STANDARD_FLOW_ENABLED,c1_0.SURROGATE_AUTH_REQUIRED from CLIENT c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.034 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.038 UTC [219] LOG:  execute <unnamed>: select a1_0.CLIENT_ID,a1_0.NAME,a1_0.VALUE from CLIENT_ATTRIBUTES a1_0 where a1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.038 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.041 UTC [219] LOG:  execute <unnamed>: select a1_0.CLIENT_ID,a1_0.BINDING_NAME,a1_0.FLOW_ID from CLIENT_AUTH_FLOW_BINDINGS a1_0 where a1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.041 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.043 UTC [219] LOG:  execute <unnamed>: select r1_0.CLIENT_ID,r1_0.VALUE from REDIRECT_URIS r1_0 where r1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.043 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.048 UTC [219] LOG:  execute <unnamed>: select w1_0.CLIENT_ID,w1_0.VALUE from WEB_ORIGINS w1_0 where w1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.048 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.052 UTC [219] LOG:  execute <unnamed>: select s1_0.CLIENT_ID,s1_0.ROLE_ID from SCOPE_MAPPING s1_0 where s1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.052 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.055 UTC [219] LOG:  execute <unnamed>: select p1_0.CLIENT_ID,p1_0.ID,p1_0.CLIENT_SCOPE_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.055 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.058 UTC [219] LOG:  execute <unnamed>: select r1_0.CLIENT_ID,r1_0.NAME,r1_0.VALUE from CLIENT_NODE_REGISTRATIONS r1_0 where r1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.058 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.061 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:31:41.061 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = 't'
docker-postgres-1  | 2023-12-03 09:31:41.064 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:31:41.064 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:31:41.069 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:31:41.069 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:31:41.071 UTC [219] LOG:  execute <unnamed>: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.071 UTC [219] DETAIL:  parameters: $1 = '24aeb2e1-da2d-4121-8419-61013dea623b'
docker-postgres-1  | 2023-12-03 09:31:41.075 UTC [219] LOG:  execute <unnamed>: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.075 UTC [219] DETAIL:  parameters: $1 = '24aeb2e1-da2d-4121-8419-61013dea623b'
docker-postgres-1  | 2023-12-03 09:31:41.077 UTC [219] LOG:  execute <unnamed>: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.077 UTC [219] DETAIL:  parameters: $1 = '5d0bee6c-e810-4623-bc2e-953989c6abcd'
docker-postgres-1  | 2023-12-03 09:31:41.080 UTC [219] LOG:  execute <unnamed>: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.080 UTC [219] DETAIL:  parameters: $1 = '24aeb2e1-da2d-4121-8419-61013dea623b'
docker-postgres-1  | 2023-12-03 09:31:41.085 UTC [219] LOG:  execute <unnamed>: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.085 UTC [219] DETAIL:  parameters: $1 = '24aeb2e1-da2d-4121-8419-61013dea623b'
docker-postgres-1  | 2023-12-03 09:31:41.089 UTC [219] LOG:  execute <unnamed>: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.089 UTC [219] DETAIL:  parameters: $1 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:31:41.091 UTC [219] LOG:  execute <unnamed>: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.091 UTC [219] DETAIL:  parameters: $1 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:31:41.095 UTC [219] LOG:  execute <unnamed>: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.095 UTC [219] DETAIL:  parameters: $1 = 'c9ca7c23-8659-47b7-a420-84e344ce69e6'
docker-postgres-1  | 2023-12-03 09:31:41.098 UTC [219] LOG:  execute <unnamed>: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.098 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619'
docker-postgres-1  | 2023-12-03 09:31:41.102 UTC [219] LOG:  execute <unnamed>: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.102 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095'
docker-postgres-1  | 2023-12-03 09:31:41.105 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.105 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7'
docker-postgres-1  | 2023-12-03 09:31:41.107 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.107 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d'
docker-postgres-1  | 2023-12-03 09:31:41.110 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.110 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126'
docker-postgres-1  | 2023-12-03 09:31:41.113 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.113 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf'
docker-postgres-1  | 2023-12-03 09:31:41.116 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.116 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050'
docker-postgres-1  | 2023-12-03 09:31:41.119 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.119 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418'
docker-postgres-1  | 2023-12-03 09:31:41.122 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.122 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb'
docker-postgres-1  | 2023-12-03 09:31:41.125 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.125 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c'
docker-postgres-1  | 2023-12-03 09:31:41.127 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.127 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd'
docker-postgres-1  | 2023-12-03 09:31:41.130 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.130 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61'
docker-postgres-1  | 2023-12-03 09:31:41.135 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.135 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e'
docker-postgres-1  | 2023-12-03 09:31:41.137 UTC [219] LOG:  execute <unnamed>: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.137 UTC [219] DETAIL:  parameters: $1 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:31:41.140 UTC [219] LOG:  execute <unnamed>: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.140 UTC [219] DETAIL:  parameters: $1 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:31:41.144 UTC [219] LOG:  execute <unnamed>: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.144 UTC [219] DETAIL:  parameters: $1 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:31:41.148 UTC [219] LOG:  execute <unnamed>: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.148 UTC [219] DETAIL:  parameters: $1 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:31:41.152 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.152 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37'
docker-postgres-1  | 2023-12-03 09:31:41.155 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.155 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1'
docker-postgres-1  | 2023-12-03 09:31:41.157 UTC [219] LOG:  execute <unnamed>: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.157 UTC [219] DETAIL:  parameters: $1 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:31:41.160 UTC [219] LOG:  execute <unnamed>: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.160 UTC [219] DETAIL:  parameters: $1 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:31:41.164 UTC [219] LOG:  execute <unnamed>: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.164 UTC [219] DETAIL:  parameters: $1 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:31:41.169 UTC [219] LOG:  execute <unnamed>: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.169 UTC [219] DETAIL:  parameters: $1 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:31:41.172 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.172 UTC [219] DETAIL:  parameters: $1 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f'
docker-postgres-1  | 2023-12-03 09:31:41.174 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.174 UTC [219] DETAIL:  parameters: $1 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6'
docker-postgres-1  | 2023-12-03 09:31:41.179 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.179 UTC [219] DETAIL:  parameters: $1 = '85fc98b4-f737-447b-8fe8-16b46bc16d6c'
docker-postgres-1  | 2023-12-03 09:31:41.182 UTC [219] LOG:  execute <unnamed>: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.182 UTC [219] DETAIL:  parameters: $1 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:31:41.186 UTC [219] LOG:  execute <unnamed>: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.186 UTC [219] DETAIL:  parameters: $1 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:31:41.190 UTC [219] LOG:  execute S_39: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.190 UTC [219] DETAIL:  parameters: $1 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:31:41.193 UTC [219] LOG:  execute S_40: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.193 UTC [219] DETAIL:  parameters: $1 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:31:41.196 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.196 UTC [219] DETAIL:  parameters: $1 = '363d81b3-966c-465c-a376-b350cc0fffde'
docker-postgres-1  | 2023-12-03 09:31:41.199 UTC [219] LOG:  execute S_41: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.199 UTC [219] DETAIL:  parameters: $1 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:31:41.203 UTC [219] LOG:  execute S_42: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.203 UTC [219] DETAIL:  parameters: $1 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:31:41.208 UTC [219] LOG:  execute S_39: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.208 UTC [219] DETAIL:  parameters: $1 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:31:41.211 UTC [219] LOG:  execute S_40: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.211 UTC [219] DETAIL:  parameters: $1 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:31:41.214 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.214 UTC [219] DETAIL:  parameters: $1 = '8a4d80da-9a87-4a54-b5f6-bee7fd3534d8'
docker-postgres-1  | 2023-12-03 09:31:41.217 UTC [219] LOG:  execute S_41: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.217 UTC [219] DETAIL:  parameters: $1 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:31:41.220 UTC [219] LOG:  execute S_42: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.220 UTC [219] DETAIL:  parameters: $1 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:31:41.226 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:31:41.226 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:31:41.229 UTC [219] LOG:  execute S_39: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.229 UTC [219] DETAIL:  parameters: $1 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:31:41.232 UTC [219] LOG:  execute S_40: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.232 UTC [219] DETAIL:  parameters: $1 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:31:41.236 UTC [219] LOG:  execute S_41: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.236 UTC [219] DETAIL:  parameters: $1 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:31:41.238 UTC [219] LOG:  execute S_32: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-03 09:31:41.238 UTC [219] DETAIL:  parameters: $1 = '9a8df9de-de60-4b23-9cbd-168869c5a26d'
docker-postgres-1  | 2023-12-03 09:31:41.244 UTC [219] LOG:  execute S_42: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.244 UTC [219] DETAIL:  parameters: $1 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:31:41.248 UTC [219] LOG:  execute S_39: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.248 UTC [219] DETAIL:  parameters: $1 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:31:41.251 UTC [219] LOG:  execute S_40: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.251 UTC [219] DETAIL:  parameters: $1 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:31:41.253 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.253 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc'
docker-postgres-1  | 2023-12-03 09:31:41.256 UTC [219] LOG:  execute S_41: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.256 UTC [219] DETAIL:  parameters: $1 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:31:41.258 UTC [219] LOG:  execute S_42: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.258 UTC [219] DETAIL:  parameters: $1 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:31:41.262 UTC [219] LOG:  execute S_39: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.262 UTC [219] DETAIL:  parameters: $1 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:31:41.265 UTC [219] LOG:  execute S_40: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.265 UTC [219] DETAIL:  parameters: $1 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:31:41.270 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.270 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c'
docker-postgres-1  | 2023-12-03 09:31:41.273 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.273 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36'
docker-postgres-1  | 2023-12-03 09:31:41.275 UTC [219] LOG:  execute S_41: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.275 UTC [219] DETAIL:  parameters: $1 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:31:41.278 UTC [219] LOG:  execute S_42: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.278 UTC [219] DETAIL:  parameters: $1 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:31:41.284 UTC [219] LOG:  execute S_39: select c1_0.ID,c1_0.DESCRIPTION,c1_0.NAME,c1_0.PROTOCOL,c1_0.REALM_ID from CLIENT_SCOPE c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.284 UTC [219] DETAIL:  parameters: $1 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:31:41.287 UTC [219] LOG:  execute S_40: select p1_0.CLIENT_SCOPE_ID,p1_0.ID,p1_0.CLIENT_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.287 UTC [219] DETAIL:  parameters: $1 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:31:41.290 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.290 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d'
docker-postgres-1  | 2023-12-03 09:31:41.292 UTC [219] LOG:  execute S_38: select c1_0.PROTOCOL_MAPPER_ID,c1_0.NAME,c1_0.VALUE from PROTOCOL_MAPPER_CONFIG c1_0 where c1_0.PROTOCOL_MAPPER_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.292 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4'
docker-postgres-1  | 2023-12-03 09:31:41.295 UTC [219] LOG:  execute S_41: select s1_0.SCOPE_ID,s1_0.ROLE_ID from CLIENT_SCOPE_ROLE_MAPPING s1_0 where s1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.295 UTC [219] DETAIL:  parameters: $1 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:31:41.298 UTC [219] LOG:  execute S_42: select a1_0.SCOPE_ID,a1_0.NAME,a1_0.VALUE from CLIENT_SCOPE_ATTRIBUTES a1_0 where a1_0.SCOPE_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.298 UTC [219] DETAIL:  parameters: $1 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:31:41.304 UTC [219] LOG:  execute <unnamed>: select s1_0.REALM_ID,s1_0.VALUE from REALM_SUPPORTED_LOCALES s1_0 where s1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.304 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.307 UTC [219] LOG:  execute <unnamed>: select a1_0.REALM_ID,a1_0.ID,a1_0.ALIAS,a1_0.BUILT_IN,a1_0.DESCRIPTION,a1_0.PROVIDER_ID,a1_0.TOP_LEVEL from AUTHENTICATION_FLOW a1_0 where a1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.307 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.312 UTC [219] LOG:  execute <unnamed>: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.312 UTC [219] DETAIL:  parameters: $1 = '0778f648-540f-41af-8719-e7f0fac82fef'
docker-postgres-1  | 2023-12-03 09:31:41.316 UTC [219] LOG:  execute <unnamed>: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.316 UTC [219] DETAIL:  parameters: $1 = '8e4e4c1d-4bfc-44c2-aeea-2dd9d68ec00d'
docker-postgres-1  | 2023-12-03 09:31:41.319 UTC [219] LOG:  execute <unnamed>: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.319 UTC [219] DETAIL:  parameters: $1 = '9bd05224-0426-4238-9206-08c655d4861d'
docker-postgres-1  | 2023-12-03 09:31:41.321 UTC [219] LOG:  execute <unnamed>: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.321 UTC [219] DETAIL:  parameters: $1 = '4599507d-63cd-4d28-a696-3513bc2ffd18'
docker-postgres-1  | 2023-12-03 09:31:41.326 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.326 UTC [219] DETAIL:  parameters: $1 = '218adc84-d74b-4a97-9100-369ccf920ade'
docker-postgres-1  | 2023-12-03 09:31:41.329 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.329 UTC [219] DETAIL:  parameters: $1 = 'e27bc65f-e3aa-44d0-8c07-e1254088b71c'
docker-postgres-1  | 2023-12-03 09:31:41.332 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.332 UTC [219] DETAIL:  parameters: $1 = '0b220305-7b56-4f05-8d38-666360f53569'
docker-postgres-1  | 2023-12-03 09:31:41.337 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.337 UTC [219] DETAIL:  parameters: $1 = '3c8bd7f1-babd-414a-bb3d-d15658d44550'
docker-postgres-1  | 2023-12-03 09:31:41.341 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.341 UTC [219] DETAIL:  parameters: $1 = 'c9289271-299d-427f-b5ff-8ea41dad7a2d'
docker-postgres-1  | 2023-12-03 09:31:41.345 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.345 UTC [219] DETAIL:  parameters: $1 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c'
docker-postgres-1  | 2023-12-03 09:31:41.348 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.348 UTC [219] DETAIL:  parameters: $1 = 'f97f67c2-6e15-42ea-a886-3907086513d7'
docker-postgres-1  | 2023-12-03 09:31:41.352 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.352 UTC [219] DETAIL:  parameters: $1 = '5e7b89e2-8925-4776-ab49-da6f7261ede8'
docker-postgres-1  | 2023-12-03 09:31:41.356 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.356 UTC [219] DETAIL:  parameters: $1 = 'f6264b3f-7533-45e9-b4d1-068c60ce3be0'
docker-postgres-1  | 2023-12-03 09:31:41.359 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.359 UTC [219] DETAIL:  parameters: $1 = 'e3bedd09-2b29-47bd-a79f-0bc1b0809e2a'
docker-postgres-1  | 2023-12-03 09:31:41.361 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.361 UTC [219] DETAIL:  parameters: $1 = '3441899b-8687-4d25-9c5b-c82a7d2c5d99'
docker-postgres-1  | 2023-12-03 09:31:41.365 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.365 UTC [219] DETAIL:  parameters: $1 = 'e5eb8fe6-40b1-4a1b-b95a-d1a067b14780'
docker-postgres-1  | 2023-12-03 09:31:41.368 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.368 UTC [219] DETAIL:  parameters: $1 = '6be71ae2-31ee-4758-8a20-c973e27d6afc'
docker-postgres-1  | 2023-12-03 09:31:41.371 UTC [219] LOG:  execute S_43: select e1_0.FLOW_ID,e1_0.ID,e1_0.AUTHENTICATOR,e1_0.AUTH_CONFIG,e1_0.AUTHENTICATOR_FLOW,e1_0.AUTH_FLOW_ID,e1_0.PRIORITY,e1_0.REALM_ID,e1_0.REQUIREMENT from AUTHENTICATION_EXECUTION e1_0 where e1_0.FLOW_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.371 UTC [219] DETAIL:  parameters: $1 = '2f492243-f94b-4334-a13d-359c2fbe6031'
docker-postgres-1  | 2023-12-03 09:31:41.374 UTC [219] LOG:  execute <unnamed>: select a1_0.REALM_ID,a1_0.ID,a1_0.ALIAS from AUTHENTICATOR_CONFIG a1_0 where a1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.374 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.377 UTC [219] LOG:  execute <unnamed>: select c1_0.AUTHENTICATOR_ID,c1_0.NAME,c1_0.VALUE from AUTHENTICATOR_CONFIG_ENTRY c1_0 where c1_0.AUTHENTICATOR_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.377 UTC [219] DETAIL:  parameters: $1 = '1c049043-b23a-4880-ac03-7a58b033d97f'
docker-postgres-1  | 2023-12-03 09:31:41.380 UTC [219] LOG:  execute <unnamed>: select c1_0.AUTHENTICATOR_ID,c1_0.NAME,c1_0.VALUE from AUTHENTICATOR_CONFIG_ENTRY c1_0 where c1_0.AUTHENTICATOR_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.380 UTC [219] DETAIL:  parameters: $1 = '87b2aff3-0155-42c4-a5d3-63cb2e6e9778'
docker-postgres-1  | 2023-12-03 09:31:41.384 UTC [219] LOG:  execute <unnamed>: select r1_0.REALM_ID,r1_0.ID,r1_0.ALIAS,r1_0.DEFAULT_ACTION,r1_0.ENABLED,r1_0.NAME,r1_0.PRIORITY,r1_0.PROVIDER_ID from REQUIRED_ACTION_PROVIDER r1_0 where r1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.384 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.387 UTC [219] LOG:  execute <unnamed>: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.387 UTC [219] DETAIL:  parameters: $1 = 'afd2e48a-e0de-4635-a51a-2ac6212b7d41'
docker-postgres-1  | 2023-12-03 09:31:41.390 UTC [219] LOG:  execute <unnamed>: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.390 UTC [219] DETAIL:  parameters: $1 = '5013a905-8954-4f53-b963-1aa3633b8c7b'
docker-postgres-1  | 2023-12-03 09:31:41.392 UTC [219] LOG:  execute <unnamed>: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.392 UTC [219] DETAIL:  parameters: $1 = 'c7b2d935-5457-4879-a534-90e6359ae759'
docker-postgres-1  | 2023-12-03 09:31:41.395 UTC [219] LOG:  execute <unnamed>: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.395 UTC [219] DETAIL:  parameters: $1 = '41b236d1-5b96-43e4-8c35-54cc0be68e7a'
docker-postgres-1  | 2023-12-03 09:31:41.397 UTC [219] LOG:  execute S_44: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.397 UTC [219] DETAIL:  parameters: $1 = '02d37cd6-ca85-4beb-9113-097834208a63'
docker-postgres-1  | 2023-12-03 09:31:41.401 UTC [219] LOG:  execute S_44: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.401 UTC [219] DETAIL:  parameters: $1 = 'c0ae5c0f-6ee5-4347-9f7c-e1026fbd5b76'
docker-postgres-1  | 2023-12-03 09:31:41.402 UTC [219] LOG:  execute S_44: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.402 UTC [219] DETAIL:  parameters: $1 = '4aceabec-b5bd-41ff-8a4b-8b1d38c11cb4'
docker-postgres-1  | 2023-12-03 09:31:41.404 UTC [219] LOG:  execute S_44: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.404 UTC [219] DETAIL:  parameters: $1 = 'd630029c-59d0-47db-b274-b8ed73b69895'
docker-postgres-1  | 2023-12-03 09:31:41.406 UTC [219] LOG:  execute S_44: select c1_0.REQUIRED_ACTION_ID,c1_0.NAME,c1_0.VALUE from REQUIRED_ACTION_CONFIG c1_0 where c1_0.REQUIRED_ACTION_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.406 UTC [219] DETAIL:  parameters: $1 = 'efd34ae8-9dcd-48c8-903f-151f30ff0c8d'
docker-postgres-1  | 2023-12-03 09:31:41.409 UTC [219] LOG:  execute <unnamed>: select d1_0.REALM_ID,d1_0.GROUP_ID from REALM_DEFAULT_GROUPS d1_0 where d1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.409 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.412 UTC [219] LOG:  execute <unnamed>: select c1_0.REALM_ID,c1_0.ID,c1_0.NAME,c1_0.PARENT_ID,c1_0.PROVIDER_ID,c1_0.PROVIDER_TYPE,c1_0.SUB_TYPE from COMPONENT c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.412 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.417 UTC [219] LOG:  execute <unnamed>: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.417 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c'
docker-postgres-1  | 2023-12-03 09:31:41.419 UTC [219] LOG:  execute <unnamed>: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.419 UTC [219] DETAIL:  parameters: $1 = '4f96b61a-0792-46ef-a50b-1c337908b78c'
docker-postgres-1  | 2023-12-03 09:31:41.421 UTC [219] LOG:  execute <unnamed>: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.421 UTC [219] DETAIL:  parameters: $1 = '3fb064a4-0ea1-45c4-b823-8940f3db9eff'
docker-postgres-1  | 2023-12-03 09:31:41.424 UTC [219] LOG:  execute <unnamed>: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.424 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9'
docker-postgres-1  | 2023-12-03 09:31:41.427 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.427 UTC [219] DETAIL:  parameters: $1 = '2e16262a-a140-45f0-9675-1f285d35f590'
docker-postgres-1  | 2023-12-03 09:31:41.430 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.430 UTC [219] DETAIL:  parameters: $1 = '666788fe-7de5-4e6b-88a2-c081b3115c7e'
docker-postgres-1  | 2023-12-03 09:31:41.433 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.433 UTC [219] DETAIL:  parameters: $1 = 'ca0ffeb5-dd26-4212-b2db-6c9c1f0079fd'
docker-postgres-1  | 2023-12-03 09:31:41.436 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.436 UTC [219] DETAIL:  parameters: $1 = '2bc03384-1ded-491c-9688-eda0f8a748ea'
docker-postgres-1  | 2023-12-03 09:31:41.438 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.438 UTC [219] DETAIL:  parameters: $1 = '5f622371-82bb-41ee-83d8-70f6a2fb5b77'
docker-postgres-1  | 2023-12-03 09:31:41.440 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.440 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec'
docker-postgres-1  | 2023-12-03 09:31:41.444 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.444 UTC [219] DETAIL:  parameters: $1 = 'ede16273-de0f-4bc8-a03d-777715b18cf3'
docker-postgres-1  | 2023-12-03 09:31:41.447 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.447 UTC [219] DETAIL:  parameters: $1 = '1f3c3d71-2100-400e-8ec7-20b5f7a3e2ab'
docker-postgres-1  | 2023-12-03 09:31:41.451 UTC [219] LOG:  execute <unnamed>: select r1_0.REALM_ID,r1_0.LOCALE,r1_0.TEXTS from REALM_LOCALIZATIONS r1_0 where r1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:31:41.451 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:31:41.456 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:31:41.456 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample-realm', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:31:41.459 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:31:41.459 UTC [219] DETAIL:  parameters: $1 = 'view-realm', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:31:41.480 UTC [219] LOG:  execute S_1: COMMIT


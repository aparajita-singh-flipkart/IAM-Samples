# Request
curl --location 'http://localhost:8080/admin/realms' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ access_token }}' \
--data '{
    "id": "fkh-customers-sample",
    "realm": "fkh-customers-sample",
    "notBefore": 0,
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
    "accessCodeLifespan": 60,
    "accessCodeLifespanUserAction": 300,
    "accessCodeLifespanLogin": 1800,
    "actionTokenGeneratedByAdminLifespan": 43200,
    "actionTokenGeneratedByUserLifespan": 300,
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
    "defaultRoles": [
        "offline_access",
        "uma_authorization"
    ],
    "requiredCredentials": [
        "password"
    ],
    "otpPolicyType": "totp",
    "otpPolicyAlgorithm": "HmacSHA1",
    "otpPolicyInitialCounter": 0,
    "otpPolicyDigits": 6,
    "otpPolicyLookAheadWindow": 1,
    "otpPolicyPeriod": 30,
    "otpSupportedApplications": [
        "FreeOTP",
        "Google Authenticator"
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
        "xRobotsTag": "none",
        "xFrameOptions": "SAMEORIGIN",
        "contentSecurityPolicy": "frame-src '\''self'\''; frame-ancestors '\''self'\''; object-src '\''none'\'';",
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
            "id": "42c7b62d-4383-42c9-a8a0-65519e2c2543",
            "name": "test-mapper",
            "identityProviderAlias": "keycloak-oidc2",
            "identityProviderMapper": "keycloak-oidc",
            "config": {}
        },
        {
            "id": "ea65c956-24c7-4587-8fe7-c07222e3485d",
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
    "attributes": {},
    "userManagedAccessAllowed": false
}'


# Response
HTTP 201


# DB Queries

docker-postgres-1  | 2023-12-03 09:25:08.299 UTC [219] LOG:  execute <unnamed>: BEGIN
docker-postgres-1  | 2023-12-03 09:25:08.302 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:08.302 UTC [219] DETAIL:  parameters: $1 = 'create-realm', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:25:08.616 UTC [219] LOG:  execute <unnamed>: insert into REALM (ACCESS_CODE_LIFESPAN,LOGIN_LIFESPAN,USER_ACTION_LIFESPAN,ACCESS_TOKEN_LIFESPAN,ACCESS_TOKEN_LIFE_IMPLICIT,ACCOUNT_THEME,ADMIN_EVENTS_DETAILS_ENABLED,ADMIN_EVENTS_ENABLED,ADMIN_THEME,ALLOW_USER_MANAGED_ACCESS,BROWSER_FLOW,CLIENT_AUTH_FLOW,DEFAULT_LOCALE,DEFAULT_ROLE,DIRECT_GRANT_FLOW,DOCKER_AUTH_FLOW,DUPLICATE_EMAILS_ALLOWED,EDIT_USERNAME_ALLOWED,EMAIL_THEME,ENABLED,EVENTS_ENABLED,EVENTS_EXPIRATION,INTERNATIONALIZATION_ENABLED,LOGIN_THEME,LOGIN_WITH_EMAIL_ALLOWED,MASTER_ADMIN_CLIENT,NAME,NOT_BEFORE,OFFLINE_SESSION_IDLE_TIMEOUT,OTP_POLICY_ALG,OTP_POLICY_DIGITS,OTP_POLICY_COUNTER,OTP_POLICY_WINDOW,OTP_POLICY_PERIOD,OTP_POLICY_TYPE,PASSWORD_POLICY,REFRESH_TOKEN_MAX_REUSE,REGISTRATION_ALLOWED,REG_EMAIL_AS_USERNAME,REGISTRATION_FLOW,REMEMBER_ME,RESET_CREDENTIALS_FLOW,RESET_PASSWORD_ALLOWED,REVOKE_REFRESH_TOKEN,SSL_REQUIRED,SSO_IDLE_TIMEOUT,SSO_IDLE_TIMEOUT_REMEMBER_ME,SSO_MAX_LIFESPAN,SSO_MAX_LIFESPAN_REMEMBER_ME,VERIFY_EMAIL,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51)
docker-postgres-1  | 2023-12-03 09:25:08.616 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = NULL, $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 'f', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 'f', $26 = NULL, $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = NULL, $31 = '0', $32 = '0', $33 = '0', $34 = '0', $35 = NULL, $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = NULL, $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.647 UTC [219] LOG:  execute <unnamed>: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.647 UTC [219] DETAIL:  parameters: $1 = '', $2 = '_browser_header.contentSecurityPolicyReportOnly', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.650 UTC [219] LOG:  execute <unnamed>: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.650 UTC [219] DETAIL:  parameters: $1 = 'nosniff', $2 = '_browser_header.xContentTypeOptions', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.653 UTC [219] LOG:  execute <unnamed>: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.653 UTC [219] DETAIL:  parameters: $1 = 'no-referrer', $2 = '_browser_header.referrerPolicy', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.658 UTC [219] LOG:  execute <unnamed>: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.658 UTC [219] DETAIL:  parameters: $1 = 'none', $2 = '_browser_header.xRobotsTag', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.666 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.666 UTC [219] DETAIL:  parameters: $1 = 'SAMEORIGIN', $2 = '_browser_header.xFrameOptions', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.670 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.670 UTC [219] DETAIL:  parameters: $1 = 'frame-src ''self''; frame-ancestors ''self''; object-src ''none'';', $2 = '_browser_header.contentSecurityPolicy', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.673 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.673 UTC [219] DETAIL:  parameters: $1 = '1; mode=block', $2 = '_browser_header.xXSSProtection', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.676 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.676 UTC [219] DETAIL:  parameters: $1 = 'max-age=31536000; includeSubDomains', $2 = '_browser_header.strictTransportSecurity', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.681 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.681 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'bruteForceProtected', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.683 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.683 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'permanentLockout', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.687 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.687 UTC [219] DETAIL:  parameters: $1 = '900', $2 = 'maxFailureWaitSeconds', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.689 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.689 UTC [219] DETAIL:  parameters: $1 = '60', $2 = 'minimumQuickLoginWaitSeconds', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.692 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.692 UTC [219] DETAIL:  parameters: $1 = '60', $2 = 'waitIncrementSeconds', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.694 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.694 UTC [219] DETAIL:  parameters: $1 = '1000', $2 = 'quickLoginCheckMilliSeconds', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.696 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.696 UTC [219] DETAIL:  parameters: $1 = '43200', $2 = 'maxDeltaTimeSeconds', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.697 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.697 UTC [219] DETAIL:  parameters: $1 = '30', $2 = 'failureFactor', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.712 UTC [219] LOG:  execute <unnamed>: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:08.712 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = NULL, $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 'f', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 'f', $26 = NULL, $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = NULL, $31 = '0', $32 = '0', $33 = '0', $34 = '0', $35 = NULL, $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.742 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:08.742 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'realmReusableOtpCode', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.750 UTC [219] LOG:  execute <unnamed>: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:08.750 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = NULL, $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 'f', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 'f', $26 = NULL, $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.768 UTC [219] LOG:  execute <unnamed>: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:08.768 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = NULL, $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 'f', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = NULL, $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.777 UTC [219] LOG:  execute <unnamed>: insert into REALM_EVENTS_LISTENERS (REALM_ID,VALUE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:08.777 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'jboss-logging'
docker-postgres-1  | 2023-12-03 09:25:08.784 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:08.784 UTC [219] DETAIL:  parameters: $1 = 'default-roles-fkh-customers-sample', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.789 UTC [219] LOG:  execute <unnamed>: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:08.789 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'fkh-customers-sample', $3 = 'f', $4 = NULL, $5 = 'default-roles-fkh-customers-sample', $6 = 'fkh-customers-sample', $7 = '12c4f394-a345-495a-be74-776f00efc836'
docker-postgres-1  | 2023-12-03 09:25:08.801 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:08.801 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample-realm', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:25:08.819 UTC [219] LOG:  execute <unnamed>: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:08.819 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 'f', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = NULL, $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.824 UTC [219] LOG:  execute <unnamed>: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:08.824 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'fkh-customers-sample', $3 = 'f', $4 = '${role_default-roles}', $5 = 'default-roles-fkh-customers-sample', $6 = 'fkh-customers-sample', $7 = '12c4f394-a345-495a-be74-776f00efc836'
docker-postgres-1  | 2023-12-03 09:25:08.834 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:08.834 UTC [219] DETAIL:  parameters: $1 = 'admin', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:25:08.842 UTC [219] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:25:08.842 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d'
docker-postgres-1  | 2023-12-03 09:25:08.858 UTC [219] LOG:  execute <unnamed>: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:08.858 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'fkh-customers-sample-realm', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:08.866 UTC [219] LOG:  execute <unnamed>: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:08.866 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 't', $4 = 'client-secret', $5 = 'fkh-customers-sample-realm', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = 'fkh-customers-sample Realm', $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:08.873 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:08.873 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 'f', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:08.892 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:08.892 UTC [219] DETAIL:  parameters: $1 = 'create-client', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:08.898 UTC [219] LOG:  execute <unnamed>: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-03 09:25:08.898 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d'
docker-postgres-1  | 2023-12-03 09:25:08.912 UTC [219] LOG:  execute <unnamed>: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:08.912 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'create-client', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '862a17e6-7729-402e-ac89-c4a883171ac2'
docker-postgres-1  | 2023-12-03 09:25:08.915 UTC [219] LOG:  execute <unnamed>: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:08.915 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_create-client}', $5 = 'create-client', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '862a17e6-7729-402e-ac89-c4a883171ac2'
docker-postgres-1  | 2023-12-03 09:25:08.928 UTC [219] LOG:  execute <unnamed>: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:08.928 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '862a17e6-7729-402e-ac89-c4a883171ac2'
docker-postgres-1  | 2023-12-03 09:25:08.937 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:08.937 UTC [219] DETAIL:  parameters: $1 = 'view-realm', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:08.947 UTC [219] LOG:  execute <unnamed>: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:08.947 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'view-realm', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '0e912919-0395-44bb-8227-82b22e69544c'
docker-postgres-1  | 2023-12-03 09:25:08.951 UTC [219] LOG:  execute <unnamed>: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:08.951 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_view-realm}', $5 = 'view-realm', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '0e912919-0395-44bb-8227-82b22e69544c'
docker-postgres-1  | 2023-12-03 09:25:08.956 UTC [219] LOG:  execute <unnamed>: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:08.956 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '0e912919-0395-44bb-8227-82b22e69544c'
docker-postgres-1  | 2023-12-03 09:25:08.962 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:08.962 UTC [219] DETAIL:  parameters: $1 = 'view-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:08.970 UTC [219] LOG:  execute <unnamed>: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:08.970 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'view-users', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '66ad1f2a-bed9-4f95-be2e-9f9d00e5f523'
docker-postgres-1  | 2023-12-03 09:25:08.973 UTC [219] LOG:  execute <unnamed>: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:08.973 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_view-users}', $5 = 'view-users', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '66ad1f2a-bed9-4f95-be2e-9f9d00e5f523'
docker-postgres-1  | 2023-12-03 09:25:08.977 UTC [219] LOG:  execute <unnamed>: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:08.977 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '66ad1f2a-bed9-4f95-be2e-9f9d00e5f523'
docker-postgres-1  | 2023-12-03 09:25:08.980 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:08.980 UTC [219] DETAIL:  parameters: $1 = 'view-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:08.999 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:08.999 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'view-clients', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '54fc9ee1-2e73-4826-a9e3-77336f56137c'
docker-postgres-1  | 2023-12-03 09:25:09.005 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.005 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_view-clients}', $5 = 'view-clients', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '54fc9ee1-2e73-4826-a9e3-77336f56137c'
docker-postgres-1  | 2023-12-03 09:25:09.008 UTC [219] LOG:  execute <unnamed>: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.008 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '54fc9ee1-2e73-4826-a9e3-77336f56137c'
docker-postgres-1  | 2023-12-03 09:25:09.010 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.010 UTC [219] DETAIL:  parameters: $1 = 'view-events', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.025 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.025 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'view-events', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '6b81e36d-d47f-470e-a652-244d16b96ef8'
docker-postgres-1  | 2023-12-03 09:25:09.032 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.032 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_view-events}', $5 = 'view-events', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '6b81e36d-d47f-470e-a652-244d16b96ef8'
docker-postgres-1  | 2023-12-03 09:25:09.035 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.035 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '6b81e36d-d47f-470e-a652-244d16b96ef8'
docker-postgres-1  | 2023-12-03 09:25:09.038 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.038 UTC [219] DETAIL:  parameters: $1 = 'view-identity-providers', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.052 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.052 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'view-identity-providers', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '5bd79518-7d2c-4bc5-8675-779a3839c112'
docker-postgres-1  | 2023-12-03 09:25:09.056 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.056 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_view-identity-providers}', $5 = 'view-identity-providers', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '5bd79518-7d2c-4bc5-8675-779a3839c112'
docker-postgres-1  | 2023-12-03 09:25:09.061 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.061 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '5bd79518-7d2c-4bc5-8675-779a3839c112'
docker-postgres-1  | 2023-12-03 09:25:09.064 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.064 UTC [219] DETAIL:  parameters: $1 = 'view-authorization', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.082 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.082 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'view-authorization', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '111b596f-af5e-4cae-9d5a-664995851c47'
docker-postgres-1  | 2023-12-03 09:25:09.087 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.087 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_view-authorization}', $5 = 'view-authorization', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '111b596f-af5e-4cae-9d5a-664995851c47'
docker-postgres-1  | 2023-12-03 09:25:09.090 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.090 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '111b596f-af5e-4cae-9d5a-664995851c47'
docker-postgres-1  | 2023-12-03 09:25:09.095 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.095 UTC [219] DETAIL:  parameters: $1 = 'manage-realm', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.105 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.105 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'manage-realm', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'ebe7ada5-ce06-46ca-88ae-d2cda627e765'
docker-postgres-1  | 2023-12-03 09:25:09.108 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.108 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_manage-realm}', $5 = 'manage-realm', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'ebe7ada5-ce06-46ca-88ae-d2cda627e765'
docker-postgres-1  | 2023-12-03 09:25:09.118 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.118 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = 'ebe7ada5-ce06-46ca-88ae-d2cda627e765'
docker-postgres-1  | 2023-12-03 09:25:09.121 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.121 UTC [219] DETAIL:  parameters: $1 = 'manage-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.131 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.131 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'manage-users', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '532fd183-929d-4cf5-be4f-822c4bac154f'
docker-postgres-1  | 2023-12-03 09:25:09.133 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.133 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_manage-users}', $5 = 'manage-users', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '532fd183-929d-4cf5-be4f-822c4bac154f'
docker-postgres-1  | 2023-12-03 09:25:09.136 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.136 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '532fd183-929d-4cf5-be4f-822c4bac154f'
docker-postgres-1  | 2023-12-03 09:25:09.140 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.140 UTC [219] DETAIL:  parameters: $1 = 'manage-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.145 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.145 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'manage-clients', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'e0800932-994a-4607-8dd3-caf9d85bdd3a'
docker-postgres-1  | 2023-12-03 09:25:09.150 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.150 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_manage-clients}', $5 = 'manage-clients', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'e0800932-994a-4607-8dd3-caf9d85bdd3a'
docker-postgres-1  | 2023-12-03 09:25:09.156 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.156 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = 'e0800932-994a-4607-8dd3-caf9d85bdd3a'
docker-postgres-1  | 2023-12-03 09:25:09.160 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.160 UTC [219] DETAIL:  parameters: $1 = 'manage-events', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.170 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.170 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'manage-events', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '6ba1c8ff-7c24-461c-bd2f-6a184ca99239'
docker-postgres-1  | 2023-12-03 09:25:09.175 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.175 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_manage-events}', $5 = 'manage-events', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '6ba1c8ff-7c24-461c-bd2f-6a184ca99239'
docker-postgres-1  | 2023-12-03 09:25:09.182 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.182 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '6ba1c8ff-7c24-461c-bd2f-6a184ca99239'
docker-postgres-1  | 2023-12-03 09:25:09.185 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.185 UTC [219] DETAIL:  parameters: $1 = 'manage-identity-providers', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.198 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.198 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'manage-identity-providers', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '34a24d1b-ad7e-4d64-8c15-6f95cbc74112'
docker-postgres-1  | 2023-12-03 09:25:09.201 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.201 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_manage-identity-providers}', $5 = 'manage-identity-providers', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '34a24d1b-ad7e-4d64-8c15-6f95cbc74112'
docker-postgres-1  | 2023-12-03 09:25:09.205 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.205 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '34a24d1b-ad7e-4d64-8c15-6f95cbc74112'
docker-postgres-1  | 2023-12-03 09:25:09.208 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.208 UTC [219] DETAIL:  parameters: $1 = 'manage-authorization', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.215 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.215 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'manage-authorization', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'a6011000-139e-4caa-a6ce-b6cf95e9951f'
docker-postgres-1  | 2023-12-03 09:25:09.216 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.216 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_manage-authorization}', $5 = 'manage-authorization', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'a6011000-139e-4caa-a6ce-b6cf95e9951f'
docker-postgres-1  | 2023-12-03 09:25:09.218 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.218 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = 'a6011000-139e-4caa-a6ce-b6cf95e9951f'
docker-postgres-1  | 2023-12-03 09:25:09.223 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.223 UTC [219] DETAIL:  parameters: $1 = 'query-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.228 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.228 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'query-users', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '3d63342c-313f-43cd-96f3-9d4ee4223e58'
docker-postgres-1  | 2023-12-03 09:25:09.232 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.232 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_query-users}', $5 = 'query-users', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '3d63342c-313f-43cd-96f3-9d4ee4223e58'
docker-postgres-1  | 2023-12-03 09:25:09.234 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.234 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '3d63342c-313f-43cd-96f3-9d4ee4223e58'
docker-postgres-1  | 2023-12-03 09:25:09.237 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.237 UTC [219] DETAIL:  parameters: $1 = 'query-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.243 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.243 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'query-clients', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '1f7abdb8-a271-4c38-9a69-ce157a850d62'
docker-postgres-1  | 2023-12-03 09:25:09.246 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.246 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_query-clients}', $5 = 'query-clients', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '1f7abdb8-a271-4c38-9a69-ce157a850d62'
docker-postgres-1  | 2023-12-03 09:25:09.250 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.250 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '1f7abdb8-a271-4c38-9a69-ce157a850d62'
docker-postgres-1  | 2023-12-03 09:25:09.256 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.256 UTC [219] DETAIL:  parameters: $1 = 'query-realms', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.265 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.265 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'query-realms', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '66b66ac8-171e-4802-89ee-2cd19ee3a2d9'
docker-postgres-1  | 2023-12-03 09:25:09.268 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.268 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_query-realms}', $5 = 'query-realms', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = '66b66ac8-171e-4802-89ee-2cd19ee3a2d9'
docker-postgres-1  | 2023-12-03 09:25:09.271 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.271 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = '66b66ac8-171e-4802-89ee-2cd19ee3a2d9'
docker-postgres-1  | 2023-12-03 09:25:09.278 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.278 UTC [219] DETAIL:  parameters: $1 = 'query-groups', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.281 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.281 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'query-groups', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'bcb1948c-2ed3-463c-b80f-ad6f41129917'
docker-postgres-1  | 2023-12-03 09:25:09.286 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.286 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_query-groups}', $5 = 'query-groups', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'bcb1948c-2ed3-463c-b80f-ad6f41129917'
docker-postgres-1  | 2023-12-03 09:25:09.291 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.291 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = 'bcb1948c-2ed3-463c-b80f-ad6f41129917'
docker-postgres-1  | 2023-12-03 09:25:09.295 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.295 UTC [219] DETAIL:  parameters: $1 = 'query-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.298 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.298 UTC [219] DETAIL:  parameters: $1 = 'query-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.305 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.305 UTC [219] DETAIL:  parameters: $1 = 'query-groups', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.316 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.316 UTC [219] DETAIL:  parameters: $1 = 'view-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.325 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.325 UTC [219] DETAIL:  parameters: $1 = 'view-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:09.333 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:09.333 UTC [219] DETAIL:  parameters: $1 = 'realm-management', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:09.339 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.339 UTC [219] DETAIL:  parameters: $1 = 'realm-admin', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.352 UTC [219] LOG:  execute <unnamed>: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.352 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:09.365 UTC [219] LOG:  execute <unnamed>: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.365 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:09.372 UTC [219] LOG:  execute <unnamed>: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.372 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:09.377 UTC [219] LOG:  execute <unnamed>: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.377 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:09.383 UTC [219] LOG:  execute <unnamed>: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:09.383 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'realm-management', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.386 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.386 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'realm-admin', $6 = 'fkh-customers-sample', $7 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e'
docker-postgres-1  | 2023-12-03 09:25:09.396 UTC [219] LOG:  execute <unnamed>: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:09.396 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 't', $4 = 'client-secret', $5 = 'realm-management', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = '${client_realm-management}', $15 = '0', $16 = '0', $17 = 'openid-connect', $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.399 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.399 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_realm-admin}', $5 = 'realm-admin', $6 = 'fkh-customers-sample', $7 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e'
docker-postgres-1  | 2023-12-03 09:25:09.400 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.400 UTC [219] DETAIL:  parameters: $1 = '54fc9ee1-2e73-4826-a9e3-77336f56137c', $2 = '1f7abdb8-a271-4c38-9a69-ce157a850d62'
docker-postgres-1  | 2023-12-03 09:25:09.403 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.403 UTC [219] DETAIL:  parameters: $1 = '66ad1f2a-bed9-4f95-be2e-9f9d00e5f523', $2 = '3d63342c-313f-43cd-96f3-9d4ee4223e58'
docker-postgres-1  | 2023-12-03 09:25:09.407 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.407 UTC [219] DETAIL:  parameters: $1 = '66ad1f2a-bed9-4f95-be2e-9f9d00e5f523', $2 = 'bcb1948c-2ed3-463c-b80f-ad6f41129917'
docker-postgres-1  | 2023-12-03 09:25:09.411 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.411 UTC [219] DETAIL:  parameters: $1 = 'create-client', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.417 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.417 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'create-client', $6 = 'fkh-customers-sample', $7 = 'e815e469-3a5e-4071-bfef-cc3604927d73'
docker-postgres-1  | 2023-12-03 09:25:09.420 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.420 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_create-client}', $5 = 'create-client', $6 = 'fkh-customers-sample', $7 = 'e815e469-3a5e-4071-bfef-cc3604927d73'
docker-postgres-1  | 2023-12-03 09:25:09.423 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.423 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'e815e469-3a5e-4071-bfef-cc3604927d73'
docker-postgres-1  | 2023-12-03 09:25:09.431 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.431 UTC [219] DETAIL:  parameters: $1 = 'view-realm', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.441 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.441 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'view-realm', $6 = 'fkh-customers-sample', $7 = 'f78934df-fdb5-41c7-b990-3fa4283bd781'
docker-postgres-1  | 2023-12-03 09:25:09.448 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.448 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_view-realm}', $5 = 'view-realm', $6 = 'fkh-customers-sample', $7 = 'f78934df-fdb5-41c7-b990-3fa4283bd781'
docker-postgres-1  | 2023-12-03 09:25:09.451 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.451 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'f78934df-fdb5-41c7-b990-3fa4283bd781'
docker-postgres-1  | 2023-12-03 09:25:09.456 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.456 UTC [219] DETAIL:  parameters: $1 = 'view-users', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.463 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.463 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'view-users', $6 = 'fkh-customers-sample', $7 = '3aa9b1fb-d99f-49e3-a079-5bc8351a3430'
docker-postgres-1  | 2023-12-03 09:25:09.464 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.464 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_view-users}', $5 = 'view-users', $6 = 'fkh-customers-sample', $7 = '3aa9b1fb-d99f-49e3-a079-5bc8351a3430'
docker-postgres-1  | 2023-12-03 09:25:09.466 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.466 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '3aa9b1fb-d99f-49e3-a079-5bc8351a3430'
docker-postgres-1  | 2023-12-03 09:25:09.470 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.470 UTC [219] DETAIL:  parameters: $1 = 'view-clients', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.485 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.485 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'view-clients', $6 = 'fkh-customers-sample', $7 = '0b9ad6ea-afb1-4376-89d5-a38b5e3e76c7'
docker-postgres-1  | 2023-12-03 09:25:09.489 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.489 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_view-clients}', $5 = 'view-clients', $6 = 'fkh-customers-sample', $7 = '0b9ad6ea-afb1-4376-89d5-a38b5e3e76c7'
docker-postgres-1  | 2023-12-03 09:25:09.492 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.492 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '0b9ad6ea-afb1-4376-89d5-a38b5e3e76c7'
docker-postgres-1  | 2023-12-03 09:25:09.494 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.494 UTC [219] DETAIL:  parameters: $1 = 'view-events', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.508 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.508 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'view-events', $6 = 'fkh-customers-sample', $7 = '71fede5e-902a-4f06-911b-097dfdd39719'
docker-postgres-1  | 2023-12-03 09:25:09.512 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.512 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_view-events}', $5 = 'view-events', $6 = 'fkh-customers-sample', $7 = '71fede5e-902a-4f06-911b-097dfdd39719'
docker-postgres-1  | 2023-12-03 09:25:09.514 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.514 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '71fede5e-902a-4f06-911b-097dfdd39719'
docker-postgres-1  | 2023-12-03 09:25:09.516 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.516 UTC [219] DETAIL:  parameters: $1 = 'view-identity-providers', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.526 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.526 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'view-identity-providers', $6 = 'fkh-customers-sample', $7 = '52db5e2a-1af8-405c-9025-204a01f15382'
docker-postgres-1  | 2023-12-03 09:25:09.530 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.530 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_view-identity-providers}', $5 = 'view-identity-providers', $6 = 'fkh-customers-sample', $7 = '52db5e2a-1af8-405c-9025-204a01f15382'
docker-postgres-1  | 2023-12-03 09:25:09.533 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.533 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '52db5e2a-1af8-405c-9025-204a01f15382'
docker-postgres-1  | 2023-12-03 09:25:09.536 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.536 UTC [219] DETAIL:  parameters: $1 = 'view-authorization', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.543 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.543 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'view-authorization', $6 = 'fkh-customers-sample', $7 = 'f00df605-f8a0-4336-90ea-c50b5dcdf4b1'
docker-postgres-1  | 2023-12-03 09:25:09.548 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.548 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_view-authorization}', $5 = 'view-authorization', $6 = 'fkh-customers-sample', $7 = 'f00df605-f8a0-4336-90ea-c50b5dcdf4b1'
docker-postgres-1  | 2023-12-03 09:25:09.556 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.556 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'f00df605-f8a0-4336-90ea-c50b5dcdf4b1'
docker-postgres-1  | 2023-12-03 09:25:09.559 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.559 UTC [219] DETAIL:  parameters: $1 = 'manage-realm', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.566 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.566 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'manage-realm', $6 = 'fkh-customers-sample', $7 = '9c066216-5dc7-491a-92a8-c424a115bf1f'
docker-postgres-1  | 2023-12-03 09:25:09.569 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.569 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_manage-realm}', $5 = 'manage-realm', $6 = 'fkh-customers-sample', $7 = '9c066216-5dc7-491a-92a8-c424a115bf1f'
docker-postgres-1  | 2023-12-03 09:25:09.573 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.573 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '9c066216-5dc7-491a-92a8-c424a115bf1f'
docker-postgres-1  | 2023-12-03 09:25:09.579 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.579 UTC [219] DETAIL:  parameters: $1 = 'manage-users', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.583 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.583 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'manage-users', $6 = 'fkh-customers-sample', $7 = 'b957d83e-ef9a-442f-b5bc-9831434813d0'
docker-postgres-1  | 2023-12-03 09:25:09.586 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.586 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_manage-users}', $5 = 'manage-users', $6 = 'fkh-customers-sample', $7 = 'b957d83e-ef9a-442f-b5bc-9831434813d0'
docker-postgres-1  | 2023-12-03 09:25:09.590 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.590 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'b957d83e-ef9a-442f-b5bc-9831434813d0'
docker-postgres-1  | 2023-12-03 09:25:09.593 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.593 UTC [219] DETAIL:  parameters: $1 = 'manage-clients', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.597 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.597 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'manage-clients', $6 = 'fkh-customers-sample', $7 = 'b1f06b87-6897-40e3-b838-1bb56fc3f467'
docker-postgres-1  | 2023-12-03 09:25:09.601 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.601 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_manage-clients}', $5 = 'manage-clients', $6 = 'fkh-customers-sample', $7 = 'b1f06b87-6897-40e3-b838-1bb56fc3f467'
docker-postgres-1  | 2023-12-03 09:25:09.604 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.604 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'b1f06b87-6897-40e3-b838-1bb56fc3f467'
docker-postgres-1  | 2023-12-03 09:25:09.606 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.606 UTC [219] DETAIL:  parameters: $1 = 'manage-events', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.611 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.611 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'manage-events', $6 = 'fkh-customers-sample', $7 = 'b8140749-f77c-4d03-9d1b-e4f1585a75b6'
docker-postgres-1  | 2023-12-03 09:25:09.619 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.619 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_manage-events}', $5 = 'manage-events', $6 = 'fkh-customers-sample', $7 = 'b8140749-f77c-4d03-9d1b-e4f1585a75b6'
docker-postgres-1  | 2023-12-03 09:25:09.622 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.622 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'b8140749-f77c-4d03-9d1b-e4f1585a75b6'
docker-postgres-1  | 2023-12-03 09:25:09.626 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.626 UTC [219] DETAIL:  parameters: $1 = 'manage-identity-providers', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.633 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.633 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'manage-identity-providers', $6 = 'fkh-customers-sample', $7 = '27bdf938-30a6-4cbc-b269-0e76e37025bc'
docker-postgres-1  | 2023-12-03 09:25:09.637 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.637 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_manage-identity-providers}', $5 = 'manage-identity-providers', $6 = 'fkh-customers-sample', $7 = '27bdf938-30a6-4cbc-b269-0e76e37025bc'
docker-postgres-1  | 2023-12-03 09:25:09.640 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.640 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '27bdf938-30a6-4cbc-b269-0e76e37025bc'
docker-postgres-1  | 2023-12-03 09:25:09.645 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.645 UTC [219] DETAIL:  parameters: $1 = 'manage-authorization', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.650 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.650 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'manage-authorization', $6 = 'fkh-customers-sample', $7 = '68b1d5e6-6821-4767-951d-0585e9f46e8b'
docker-postgres-1  | 2023-12-03 09:25:09.654 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.654 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_manage-authorization}', $5 = 'manage-authorization', $6 = 'fkh-customers-sample', $7 = '68b1d5e6-6821-4767-951d-0585e9f46e8b'
docker-postgres-1  | 2023-12-03 09:25:09.663 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.663 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '68b1d5e6-6821-4767-951d-0585e9f46e8b'
docker-postgres-1  | 2023-12-03 09:25:09.665 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.665 UTC [219] DETAIL:  parameters: $1 = 'query-users', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.673 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.673 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'query-users', $6 = 'fkh-customers-sample', $7 = '282436e4-701d-4217-85be-cb7ed69aa6e0'
docker-postgres-1  | 2023-12-03 09:25:09.675 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.675 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_query-users}', $5 = 'query-users', $6 = 'fkh-customers-sample', $7 = '282436e4-701d-4217-85be-cb7ed69aa6e0'
docker-postgres-1  | 2023-12-03 09:25:09.681 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.681 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '282436e4-701d-4217-85be-cb7ed69aa6e0'
docker-postgres-1  | 2023-12-03 09:25:09.683 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.683 UTC [219] DETAIL:  parameters: $1 = 'query-clients', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.695 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.695 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'query-clients', $6 = 'fkh-customers-sample', $7 = '524504a3-4e1b-42ab-8540-241f0b306355'
docker-postgres-1  | 2023-12-03 09:25:09.704 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.704 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_query-clients}', $5 = 'query-clients', $6 = 'fkh-customers-sample', $7 = '524504a3-4e1b-42ab-8540-241f0b306355'
docker-postgres-1  | 2023-12-03 09:25:09.706 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.706 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '524504a3-4e1b-42ab-8540-241f0b306355'
docker-postgres-1  | 2023-12-03 09:25:09.709 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.709 UTC [219] DETAIL:  parameters: $1 = 'query-realms', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.715 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.715 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'query-realms', $6 = 'fkh-customers-sample', $7 = '7ed504ee-0d80-4f11-8bfd-4f85d8472999'
docker-postgres-1  | 2023-12-03 09:25:09.717 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.717 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_query-realms}', $5 = 'query-realms', $6 = 'fkh-customers-sample', $7 = '7ed504ee-0d80-4f11-8bfd-4f85d8472999'
docker-postgres-1  | 2023-12-03 09:25:09.722 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.722 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '7ed504ee-0d80-4f11-8bfd-4f85d8472999'
docker-postgres-1  | 2023-12-03 09:25:09.731 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.731 UTC [219] DETAIL:  parameters: $1 = 'query-groups', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.736 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.736 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'query-groups', $6 = 'fkh-customers-sample', $7 = '8eca6e35-b72d-49ee-a5fe-9f3fdd65d213'
docker-postgres-1  | 2023-12-03 09:25:09.739 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.739 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_query-groups}', $5 = 'query-groups', $6 = 'fkh-customers-sample', $7 = '8eca6e35-b72d-49ee-a5fe-9f3fdd65d213'
docker-postgres-1  | 2023-12-03 09:25:09.742 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.742 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = '8eca6e35-b72d-49ee-a5fe-9f3fdd65d213'
docker-postgres-1  | 2023-12-03 09:25:09.745 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.745 UTC [219] DETAIL:  parameters: $1 = 'query-clients', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.751 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.751 UTC [219] DETAIL:  parameters: $1 = 'query-users', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.757 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.757 UTC [219] DETAIL:  parameters: $1 = 'query-groups', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.763 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.763 UTC [219] DETAIL:  parameters: $1 = 'view-clients', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.767 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.767 UTC [219] DETAIL:  parameters: $1 = 'view-users', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:09.775 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:09.775 UTC [219] DETAIL:  parameters: $1 = 'account', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:09.784 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.784 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:09.796 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.796 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:09.800 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.800 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:09.805 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:09.805 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:09.818 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.818 UTC [219] DETAIL:  parameters: $1 = 'view-profile', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.826 UTC [219] LOG:  execute <unnamed>: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:09.826 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'account', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.830 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_ATTRIBUTES (VALUE,CLIENT_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:09.830 UTC [219] DETAIL:  parameters: $1 = '+', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'post.logout.redirect.uris'
docker-postgres-1  | 2023-12-03 09:25:09.835 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.835 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'view-profile', $6 = 'fkh-customers-sample', $7 = 'a299c3b1-ab37-41b5-af0b-2324c616dcfc'
docker-postgres-1  | 2023-12-03 09:25:09.839 UTC [219] LOG:  execute <unnamed>: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:09.839 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '/realms/fkh-customers-sample/account/', $3 = 'f', $4 = 'client-secret', $5 = 'account', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = '${client_account}', $15 = '0', $16 = '0', $17 = 'openid-connect', $18 = 't', $19 = 'fkh-customers-sample', $20 = NULL, $21 = '${authBaseUrl}', $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.845 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.845 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_view-profile}', $5 = 'view-profile', $6 = 'fkh-customers-sample', $7 = 'a299c3b1-ab37-41b5-af0b-2324c616dcfc'
docker-postgres-1  | 2023-12-03 09:25:09.849 UTC [219] LOG:  execute <unnamed>: insert into REDIRECT_URIS (CLIENT_ID,VALUE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.849 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '/realms/fkh-customers-sample/account/*'
docker-postgres-1  | 2023-12-03 09:25:09.852 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.852 UTC [219] DETAIL:  parameters: $1 = '0b9ad6ea-afb1-4376-89d5-a38b5e3e76c7', $2 = '524504a3-4e1b-42ab-8540-241f0b306355'
docker-postgres-1  | 2023-12-03 09:25:09.859 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.859 UTC [219] DETAIL:  parameters: $1 = '12c4f394-a345-495a-be74-776f00efc836', $2 = 'a299c3b1-ab37-41b5-af0b-2324c616dcfc'
docker-postgres-1  | 2023-12-03 09:25:09.865 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.865 UTC [219] DETAIL:  parameters: $1 = '3aa9b1fb-d99f-49e3-a079-5bc8351a3430', $2 = '282436e4-701d-4217-85be-cb7ed69aa6e0'
docker-postgres-1  | 2023-12-03 09:25:09.868 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.868 UTC [219] DETAIL:  parameters: $1 = '3aa9b1fb-d99f-49e3-a079-5bc8351a3430', $2 = '8eca6e35-b72d-49ee-a5fe-9f3fdd65d213'
docker-postgres-1  | 2023-12-03 09:25:09.872 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.872 UTC [219] DETAIL:  parameters: $1 = 'manage-account', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.882 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.882 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'manage-account', $6 = 'fkh-customers-sample', $7 = 'a60bb735-89f2-45b4-ad66-3608d65d6b2e'
docker-postgres-1  | 2023-12-03 09:25:09.885 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.885 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_manage-account}', $5 = 'manage-account', $6 = 'fkh-customers-sample', $7 = 'a60bb735-89f2-45b4-ad66-3608d65d6b2e'
docker-postgres-1  | 2023-12-03 09:25:09.889 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.889 UTC [219] DETAIL:  parameters: $1 = '12c4f394-a345-495a-be74-776f00efc836', $2 = 'a60bb735-89f2-45b4-ad66-3608d65d6b2e'
docker-postgres-1  | 2023-12-03 09:25:09.893 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.893 UTC [219] DETAIL:  parameters: $1 = 'manage-account-links', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.899 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.899 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'manage-account-links', $6 = 'fkh-customers-sample', $7 = 'cd6c7255-ec37-49de-9618-bc697b8fa16f'
docker-postgres-1  | 2023-12-03 09:25:09.902 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.902 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_manage-account-links}', $5 = 'manage-account-links', $6 = 'fkh-customers-sample', $7 = 'cd6c7255-ec37-49de-9618-bc697b8fa16f'
docker-postgres-1  | 2023-12-03 09:25:09.907 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.907 UTC [219] DETAIL:  parameters: $1 = 'manage-account', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.912 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.912 UTC [219] DETAIL:  parameters: $1 = 'view-applications', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.921 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.921 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'view-applications', $6 = 'fkh-customers-sample', $7 = '877874cc-be3a-4888-a3ae-f0c3e68e17fd'
docker-postgres-1  | 2023-12-03 09:25:09.926 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.926 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_view-applications}', $5 = 'view-applications', $6 = 'fkh-customers-sample', $7 = '877874cc-be3a-4888-a3ae-f0c3e68e17fd'
docker-postgres-1  | 2023-12-03 09:25:09.931 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.931 UTC [219] DETAIL:  parameters: $1 = 'a60bb735-89f2-45b4-ad66-3608d65d6b2e', $2 = 'cd6c7255-ec37-49de-9618-bc697b8fa16f'
docker-postgres-1  | 2023-12-03 09:25:09.937 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.937 UTC [219] DETAIL:  parameters: $1 = 'view-consent', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.950 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.950 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'view-consent', $6 = 'fkh-customers-sample', $7 = '31fc52b9-3460-4fd9-912d-3402dcb31bba'
docker-postgres-1  | 2023-12-03 09:25:09.956 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.956 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_view-consent}', $5 = 'view-consent', $6 = 'fkh-customers-sample', $7 = '31fc52b9-3460-4fd9-912d-3402dcb31bba'
docker-postgres-1  | 2023-12-03 09:25:09.961 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.961 UTC [219] DETAIL:  parameters: $1 = 'manage-consent', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.970 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.970 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'manage-consent', $6 = 'fkh-customers-sample', $7 = '7d99ffd9-a76a-487f-875e-29bca2a61f26'
docker-postgres-1  | 2023-12-03 09:25:09.973 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.973 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_manage-consent}', $5 = 'manage-consent', $6 = 'fkh-customers-sample', $7 = '7d99ffd9-a76a-487f-875e-29bca2a61f26'
docker-postgres-1  | 2023-12-03 09:25:09.978 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:09.978 UTC [219] DETAIL:  parameters: $1 = '7d99ffd9-a76a-487f-875e-29bca2a61f26', $2 = '31fc52b9-3460-4fd9-912d-3402dcb31bba'
docker-postgres-1  | 2023-12-03 09:25:09.983 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.983 UTC [219] DETAIL:  parameters: $1 = 'view-groups', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:09.989 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:09.989 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'view-groups', $6 = 'fkh-customers-sample', $7 = '61d9b1d5-861e-4922-90a3-147253113856'
docker-postgres-1  | 2023-12-03 09:25:09.993 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:09.993 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_view-groups}', $5 = 'view-groups', $6 = 'fkh-customers-sample', $7 = '61d9b1d5-861e-4922-90a3-147253113856'
docker-postgres-1  | 2023-12-03 09:25:09.996 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:09.996 UTC [219] DETAIL:  parameters: $1 = 'delete-account', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:10.007 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.007 UTC [219] DETAIL:  parameters: $1 = 'delete-account', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:10.017 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.017 UTC [219] DETAIL:  parameters: $1 = 'account-console', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.028 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.028 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.041 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.041 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.049 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.049 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.058 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.058 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.068 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:10.068 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = NULL, $5 = 'delete-account', $6 = 'fkh-customers-sample', $7 = 'df8a6574-c1c6-4561-84a5-682acba6c18e'
docker-postgres-1  | 2023-12-03 09:25:10.077 UTC [219] LOG:  execute <unnamed>: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:10.077 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'account-console', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '5229c301-fe3e-493c-b403-c5ca1ee4e579'
docker-postgres-1  | 2023-12-03 09:25:10.080 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_ATTRIBUTES (VALUE,CLIENT_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.080 UTC [219] DETAIL:  parameters: $1 = '+', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'post.logout.redirect.uris'
docker-postgres-1  | 2023-12-03 09:25:10.086 UTC [219] LOG:  execute <unnamed>: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:10.086 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '/realms/fkh-customers-sample/account/', $3 = 'f', $4 = 'client-secret', $5 = 'account-console', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = '${client_account-console}', $15 = '0', $16 = '0', $17 = 'openid-connect', $18 = 't', $19 = 'fkh-customers-sample', $20 = NULL, $21 = '${authBaseUrl}', $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '5229c301-fe3e-493c-b403-c5ca1ee4e579'
docker-postgres-1  | 2023-12-03 09:25:10.090 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:10.090 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 't', $4 = '${role_delete-account}', $5 = 'delete-account', $6 = 'fkh-customers-sample', $7 = 'df8a6574-c1c6-4561-84a5-682acba6c18e'
docker-postgres-1  | 2023-12-03 09:25:10.094 UTC [219] LOG:  execute <unnamed>: insert into REDIRECT_URIS (CLIENT_ID,VALUE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.094 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = '/realms/fkh-customers-sample/account/*'
docker-postgres-1  | 2023-12-03 09:25:10.096 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.096 UTC [219] DETAIL:  parameters: $1 = 'manage-account', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:10.105 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.105 UTC [219] DETAIL:  parameters: $1 = 'view-groups', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:10.122 UTC [219] LOG:  execute <unnamed>: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.122 UTC [219] DETAIL:  parameters: $1 = 'admin', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:25:10.133 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.133 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample-realm', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:25:10.146 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.146 UTC [219] DETAIL:  parameters: $1 = 'impersonation', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:10.157 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.157 UTC [219] DETAIL:  parameters: $1 = 'impersonation', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:10.167 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.167 UTC [219] DETAIL:  parameters: $1 = 'realm-management', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.175 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.175 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = NULL, $3 = 'audience resolve', $4 = 'openid-connect', $5 = 'oidc-audience-resolve-mapper', $6 = 'ecf5bfb3-09a7-4f68-8c24-ed700f9e5747'
docker-postgres-1  | 2023-12-03 09:25:10.181 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_ATTRIBUTES (VALUE,CLIENT_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.181 UTC [219] DETAIL:  parameters: $1 = 'S256', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'pkce.code.challenge.method'
docker-postgres-1  | 2023-12-03 09:25:10.185 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:10.185 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = NULL, $5 = 'impersonation', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'e7020437-8964-473d-8e53-5c157f9be653'
docker-postgres-1  | 2023-12-03 09:25:10.189 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:10.189 UTC [219] DETAIL:  parameters: $1 = '452726be-5e71-4e63-b92a-5df65c91569e', $2 = '452726be-5e71-4e63-b92a-5df65c91569e', $3 = 't', $4 = '${role_impersonation}', $5 = 'impersonation', $6 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $7 = 'e7020437-8964-473d-8e53-5c157f9be653'
docker-postgres-1  | 2023-12-03 09:25:10.193 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.193 UTC [219] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d', $2 = 'e7020437-8964-473d-8e53-5c157f9be653'
docker-postgres-1  | 2023-12-03 09:25:10.197 UTC [219] LOG:  execute <unnamed>: insert into SCOPE_MAPPING (CLIENT_ID,ROLE_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.197 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 'a60bb735-89f2-45b4-ad66-3608d65d6b2e'
docker-postgres-1  | 2023-12-03 09:25:10.202 UTC [219] LOG:  execute <unnamed>: insert into SCOPE_MAPPING (CLIENT_ID,ROLE_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.202 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = '61d9b1d5-861e-4922-90a3-147253113856'
docker-postgres-1  | 2023-12-03 09:25:10.206 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.206 UTC [219] DETAIL:  parameters: $1 = 'impersonation', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:10.221 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.221 UTC [219] DETAIL:  parameters: $1 = 'impersonation', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:10.231 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:10.231 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = NULL, $5 = 'impersonation', $6 = 'fkh-customers-sample', $7 = 'ec55afe5-2955-45be-ad5a-ec47cfb87940'
docker-postgres-1  | 2023-12-03 09:25:10.235 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:10.235 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 't', $4 = '${role_impersonation}', $5 = 'impersonation', $6 = 'fkh-customers-sample', $7 = 'ec55afe5-2955-45be-ad5a-ec47cfb87940'
docker-postgres-1  | 2023-12-03 09:25:10.239 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.239 UTC [219] DETAIL:  parameters: $1 = 'realm-admin', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518'
docker-postgres-1  | 2023-12-03 09:25:10.248 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.248 UTC [219] DETAIL:  parameters: $1 = 'broker', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.256 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.256 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.263 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.263 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.267 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.267 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.274 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.274 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.284 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:10.284 UTC [219] DETAIL:  parameters: $1 = 'read-token', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567'
docker-postgres-1  | 2023-12-03 09:25:10.295 UTC [219] LOG:  execute S_11: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:10.295 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'broker', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567'
docker-postgres-1  | 2023-12-03 09:25:10.301 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:10.301 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 't', $4 = NULL, $5 = 'read-token', $6 = 'fkh-customers-sample', $7 = '2781cc21-e3fa-407e-8580-a4baddc91df3'
docker-postgres-1  | 2023-12-03 09:25:10.305 UTC [219] LOG:  execute S_12: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:10.305 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 't', $4 = 'client-secret', $5 = 'broker', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = '${client_broker}', $15 = '0', $16 = '0', $17 = 'openid-connect', $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567'
docker-postgres-1  | 2023-12-03 09:25:10.312 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:10.312 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 't', $4 = '${role_read-token}', $5 = 'read-token', $6 = 'fkh-customers-sample', $7 = '2781cc21-e3fa-407e-8580-a4baddc91df3'
docker-postgres-1  | 2023-12-03 09:25:10.315 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.315 UTC [219] DETAIL:  parameters: $1 = '9a8433f7-631f-45ba-b453-0ba8f1b4c24e', $2 = 'ec55afe5-2955-45be-ad5a-ec47cfb87940'
docker-postgres-1  | 2023-12-03 09:25:10.319 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.319 UTC [219] DETAIL:  parameters: $1 = 'security-admin-console', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.340 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.340 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.345 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.345 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.352 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.352 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.360 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.360 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.368 UTC [219] LOG:  execute S_11: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:10.368 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'security-admin-console', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '63310b6e-7601-42ce-86a9-b008c64c019d'
docker-postgres-1  | 2023-12-03 09:25:10.375 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_ATTRIBUTES (VALUE,CLIENT_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.375 UTC [219] DETAIL:  parameters: $1 = '+', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'post.logout.redirect.uris'
docker-postgres-1  | 2023-12-03 09:25:10.382 UTC [219] LOG:  execute S_13: insert into CLIENT_ATTRIBUTES (VALUE,CLIENT_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.382 UTC [219] DETAIL:  parameters: $1 = 'S256', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'pkce.code.challenge.method'
docker-postgres-1  | 2023-12-03 09:25:10.388 UTC [219] LOG:  execute S_12: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:10.388 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '/admin/fkh-customers-sample/console/', $3 = 'f', $4 = 'client-secret', $5 = 'security-admin-console', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = '${client_security-admin-console}', $15 = '0', $16 = '0', $17 = 'openid-connect', $18 = 't', $19 = 'fkh-customers-sample', $20 = NULL, $21 = '${authAdminUrl}', $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = '63310b6e-7601-42ce-86a9-b008c64c019d'
docker-postgres-1  | 2023-12-03 09:25:10.393 UTC [219] LOG:  execute <unnamed>: insert into REDIRECT_URIS (CLIENT_ID,VALUE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.393 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = '/admin/fkh-customers-sample/console/*'
docker-postgres-1  | 2023-12-03 09:25:10.402 UTC [219] LOG:  execute <unnamed>: insert into WEB_ORIGINS (CLIENT_ID,VALUE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.402 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = '+'
docker-postgres-1  | 2023-12-03 09:25:10.416 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.416 UTC [219] DETAIL:  parameters: $1 = 'admin-cli', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.423 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.423 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.438 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.438 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.452 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.452 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.466 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.466 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.477 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.477 UTC [219] DETAIL:  parameters: $1 = 'offline_access', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.505 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:10.505 UTC [219] DETAIL:  parameters: $1 = 'offline_access', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.518 UTC [219] LOG:  execute S_11: insert into CLIENT (ALWAYS_DISPLAY_IN_CONSOLE,BASE_URL,BEARER_ONLY,CLIENT_AUTHENTICATOR_TYPE,CLIENT_ID,CONSENT_REQUIRED,DESCRIPTION,DIRECT_ACCESS_GRANTS_ENABLED,ENABLED,FRONTCHANNEL_LOGOUT,FULL_SCOPE_ALLOWED,IMPLICIT_FLOW_ENABLED,MANAGEMENT_URL,NAME,NODE_REREG_TIMEOUT,NOT_BEFORE,PROTOCOL,PUBLIC_CLIENT,REALM_ID,REGISTRATION_TOKEN,ROOT_URL,SECRET,SERVICE_ACCOUNTS_ENABLED,STANDARD_FLOW_ENABLED,SURROGATE_AUTH_REQUIRED,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
docker-postgres-1  | 2023-12-03 09:25:10.518 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'admin-cli', $6 = 'f', $7 = NULL, $8 = 'f', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = NULL, $15 = '0', $16 = '0', $17 = NULL, $18 = 'f', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 't', $25 = 'f', $26 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028'
docker-postgres-1  | 2023-12-03 09:25:10.528 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:10.528 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'fkh-customers-sample', $3 = 'f', $4 = NULL, $5 = 'offline_access', $6 = 'fkh-customers-sample', $7 = '9a8df9de-de60-4b23-9cbd-168869c5a26d'
docker-postgres-1  | 2023-12-03 09:25:10.537 UTC [219] LOG:  execute S_12: update CLIENT set ALWAYS_DISPLAY_IN_CONSOLE=$1,BASE_URL=$2,BEARER_ONLY=$3,CLIENT_AUTHENTICATOR_TYPE=$4,CLIENT_ID=$5,CONSENT_REQUIRED=$6,DESCRIPTION=$7,DIRECT_ACCESS_GRANTS_ENABLED=$8,ENABLED=$9,FRONTCHANNEL_LOGOUT=$10,FULL_SCOPE_ALLOWED=$11,IMPLICIT_FLOW_ENABLED=$12,MANAGEMENT_URL=$13,NAME=$14,NODE_REREG_TIMEOUT=$15,NOT_BEFORE=$16,PROTOCOL=$17,PUBLIC_CLIENT=$18,REALM_ID=$19,REGISTRATION_TOKEN=$20,ROOT_URL=$21,SECRET=$22,SERVICE_ACCOUNTS_ENABLED=$23,STANDARD_FLOW_ENABLED=$24,SURROGATE_AUTH_REQUIRED=$25 where ID=$26
docker-postgres-1  | 2023-12-03 09:25:10.537 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = NULL, $3 = 'f', $4 = 'client-secret', $5 = 'admin-cli', $6 = 'f', $7 = NULL, $8 = 't', $9 = 't', $10 = 'f', $11 = 'f', $12 = 'f', $13 = NULL, $14 = '${client_admin-cli}', $15 = '0', $16 = '0', $17 = 'openid-connect', $18 = 't', $19 = 'fkh-customers-sample', $20 = NULL, $21 = NULL, $22 = NULL, $23 = 'f', $24 = 'f', $25 = 'f', $26 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028'
docker-postgres-1  | 2023-12-03 09:25:10.552 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:10.552 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'offline_access', $3 = NULL, $4 = 'fkh-customers-sample', $5 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:10.565 UTC [219] LOG:  execute S_6: update KEYCLOAK_ROLE set CLIENT=$1,CLIENT_REALM_CONSTRAINT=$2,CLIENT_ROLE=$3,DESCRIPTION=$4,NAME=$5,REALM_ID=$6 where ID=$7
docker-postgres-1  | 2023-12-03 09:25:10.565 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'fkh-customers-sample', $3 = 'f', $4 = '${role_offline-access}', $5 = 'offline_access', $6 = 'fkh-customers-sample', $7 = '9a8df9de-de60-4b23-9cbd-168869c5a26d'
docker-postgres-1  | 2023-12-03 09:25:10.569 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.569 UTC [219] DETAIL:  parameters: $1 = '12c4f394-a345-495a-be74-776f00efc836', $2 = '9a8df9de-de60-4b23-9cbd-168869c5a26d'
docker-postgres-1  | 2023-12-03 09:25:10.586 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.586 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:10.590 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.590 UTC [219] DETAIL:  parameters: $1 = '${offlineAccessScopeConsentText}', $2 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:10.592 UTC [219] LOG:  execute <unnamed>: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.592 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.598 UTC [219] LOG:  execute <unnamed>: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:10.598 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect built-in scope: offline_access', $2 = 'offline_access', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:10.601 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_ROLE_MAPPING (SCOPE_ID,ROLE_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:10.601 UTC [219] DETAIL:  parameters: $1 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422', $2 = '9a8df9de-de60-4b23-9cbd-168869c5a26d'
docker-postgres-1  | 2023-12-03 09:25:10.618 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:10.618 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'role_list', $3 = NULL, $4 = 'fkh-customers-sample', $5 = '24aeb2e1-da2d-4121-8419-61013dea623b'
docker-postgres-1  | 2023-12-03 09:25:10.636 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.636 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = '24aeb2e1-da2d-4121-8419-61013dea623b', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:10.640 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.640 UTC [219] DETAIL:  parameters: $1 = '${samlRoleListScopeConsentText}', $2 = '24aeb2e1-da2d-4121-8419-61013dea623b', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:10.643 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.643 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '24aeb2e1-da2d-4121-8419-61013dea623b', $3 = 'role list', $4 = 'saml', $5 = 'saml-role-list-mapper', $6 = '5d0bee6c-e810-4623-bc2e-953989c6abcd'
docker-postgres-1  | 2023-12-03 09:25:10.645 UTC [219] LOG:  execute <unnamed>: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.645 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '24aeb2e1-da2d-4121-8419-61013dea623b', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.649 UTC [219] LOG:  execute <unnamed>: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:10.649 UTC [219] DETAIL:  parameters: $1 = 'SAML role list', $2 = 'role_list', $3 = 'saml', $4 = 'fkh-customers-sample', $5 = '24aeb2e1-da2d-4121-8419-61013dea623b'
docker-postgres-1  | 2023-12-03 09:25:10.662 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.662 UTC [219] DETAIL:  parameters: $1 = '5d0bee6c-e810-4623-bc2e-953989c6abcd', $2 = 'single', $3 = 'false'
docker-postgres-1  | 2023-12-03 09:25:10.673 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.673 UTC [219] DETAIL:  parameters: $1 = '5d0bee6c-e810-4623-bc2e-953989c6abcd', $2 = 'attribute.nameformat', $3 = 'Basic'
docker-postgres-1  | 2023-12-03 09:25:10.676 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.676 UTC [219] DETAIL:  parameters: $1 = '5d0bee6c-e810-4623-bc2e-953989c6abcd', $2 = 'attribute.name', $3 = 'Role'
docker-postgres-1  | 2023-12-03 09:25:10.699 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.699 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.718 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.718 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.730 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.REALM_ID=$1 order by c1_0.CLIENT_ID
docker-postgres-1  | 2023-12-03 09:25:10.730 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:10.768 UTC [219] LOG:  execute <unnamed>: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.768 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.780 UTC [219] LOG:  execute <unnamed>: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.780 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.812 UTC [219] LOG:  execute <unnamed>: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.812 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.820 UTC [219] LOG:  execute <unnamed>: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.820 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.830 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.830 UTC [219] DETAIL:  parameters: $1 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.836 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.836 UTC [219] DETAIL:  parameters: $1 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.846 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.846 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.851 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.851 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.855 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.855 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.863 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.863 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.867 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.867 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:10.874 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:10.874 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:10.882 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:10.882 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'profile', $3 = NULL, $4 = 'fkh-customers-sample', $5 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:10.895 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.895 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:10.899 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.899 UTC [219] DETAIL:  parameters: $1 = '${profileScopeConsentText}', $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:10.902 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.902 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:10.906 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.906 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'full name', $4 = 'openid-connect', $5 = 'oidc-full-name-mapper', $6 = 'c9ca7c23-8659-47b7-a420-84e344ce69e6'
docker-postgres-1  | 2023-12-03 09:25:10.911 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.911 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'family name', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619'
docker-postgres-1  | 2023-12-03 09:25:10.916 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.916 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'given name', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '9c849da1-60ad-4b0f-92df-f96284e9b095'
docker-postgres-1  | 2023-12-03 09:25:10.919 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.919 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'middle name', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7'
docker-postgres-1  | 2023-12-03 09:25:10.924 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.924 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'nickname', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d'
docker-postgres-1  | 2023-12-03 09:25:10.930 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.930 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'username', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '8f7e111f-5fcd-4451-8769-ab69e10d6126'
docker-postgres-1  | 2023-12-03 09:25:10.932 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.932 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'profile', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '1c2bffcb-4969-43e2-8491-d5317d2140bf'
docker-postgres-1  | 2023-12-03 09:25:10.936 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.936 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'picture', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050'
docker-postgres-1  | 2023-12-03 09:25:10.940 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.940 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'website', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418'
docker-postgres-1  | 2023-12-03 09:25:10.945 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.945 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'gender', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb'
docker-postgres-1  | 2023-12-03 09:25:10.947 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.947 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'birthdate', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '97b13547-5c2b-45ca-90b1-0cf35f06596c'
docker-postgres-1  | 2023-12-03 09:25:10.949 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.949 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'zoneinfo', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd'
docker-postgres-1  | 2023-12-03 09:25:10.951 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.951 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'locale', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'ad100a61-5299-41f1-9303-e9021b36cf61'
docker-postgres-1  | 2023-12-03 09:25:10.954 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:10.954 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'updated at', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e'
docker-postgres-1  | 2023-12-03 09:25:10.957 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:10.957 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'email', $3 = NULL, $4 = 'fkh-customers-sample', $5 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:10.962 UTC [219] LOG:  execute <unnamed>: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:10.962 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect built-in scope: profile', $2 = 'profile', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:10.967 UTC [219] LOG:  execute <unnamed>: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.967 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:10.970 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.970 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7', $2 = 'user.attribute', $3 = 'middleName'
docker-postgres-1  | 2023-12-03 09:25:10.977 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.977 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:10.982 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.982 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:10.986 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.986 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7', $2 = 'claim.name', $3 = 'middle_name'
docker-postgres-1  | 2023-12-03 09:25:10.990 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.990 UTC [219] DETAIL:  parameters: $1 = '18c93b93-22c2-4f8d-a46a-61f333e3a9d7', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:10.996 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.996 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:10.998 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:10.998 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf', $2 = 'user.attribute', $3 = 'profile'
docker-postgres-1  | 2023-12-03 09:25:11.001 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.001 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.005 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.005 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.010 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.010 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf', $2 = 'claim.name', $3 = 'profile'
docker-postgres-1  | 2023-12-03 09:25:11.014 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.014 UTC [219] DETAIL:  parameters: $1 = '1c2bffcb-4969-43e2-8491-d5317d2140bf', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.019 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.019 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.026 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.026 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e', $2 = 'user.attribute', $3 = 'updatedAt'
docker-postgres-1  | 2023-12-03 09:25:11.030 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.030 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.032 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.032 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.035 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.035 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e', $2 = 'claim.name', $3 = 'updated_at'
docker-postgres-1  | 2023-12-03 09:25:11.038 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.038 UTC [219] DETAIL:  parameters: $1 = '47d70b88-1cb0-4b36-8630-afbe8dbfa34e', $2 = 'jsonType.label', $3 = 'long'
docker-postgres-1  | 2023-12-03 09:25:11.041 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.041 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.045 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.045 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619', $2 = 'user.attribute', $3 = 'lastName'
docker-postgres-1  | 2023-12-03 09:25:11.052 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.052 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.054 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.054 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.057 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.057 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619', $2 = 'claim.name', $3 = 'family_name'
docker-postgres-1  | 2023-12-03 09:25:11.062 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.062 UTC [219] DETAIL:  parameters: $1 = '7f53b85a-ade9-41ef-a7f8-da1cf597d619', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.066 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.066 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.070 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.070 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126', $2 = 'user.attribute', $3 = 'username'
docker-postgres-1  | 2023-12-03 09:25:11.075 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.075 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.080 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.080 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.084 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.084 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126', $2 = 'claim.name', $3 = 'preferred_username'
docker-postgres-1  | 2023-12-03 09:25:11.088 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.088 UTC [219] DETAIL:  parameters: $1 = '8f7e111f-5fcd-4451-8769-ab69e10d6126', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.102 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.102 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.113 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.113 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c', $2 = 'user.attribute', $3 = 'birthdate'
docker-postgres-1  | 2023-12-03 09:25:11.114 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.114 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.117 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.117 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.121 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.121 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c', $2 = 'claim.name', $3 = 'birthdate'
docker-postgres-1  | 2023-12-03 09:25:11.125 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.125 UTC [219] DETAIL:  parameters: $1 = '97b13547-5c2b-45ca-90b1-0cf35f06596c', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.133 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.133 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.136 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.136 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095', $2 = 'user.attribute', $3 = 'firstName'
docker-postgres-1  | 2023-12-03 09:25:11.139 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.139 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.145 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.145 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.149 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.149 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095', $2 = 'claim.name', $3 = 'given_name'
docker-postgres-1  | 2023-12-03 09:25:11.153 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.153 UTC [219] DETAIL:  parameters: $1 = '9c849da1-60ad-4b0f-92df-f96284e9b095', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.158 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.158 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.163 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.163 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd', $2 = 'user.attribute', $3 = 'zoneinfo'
docker-postgres-1  | 2023-12-03 09:25:11.167 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.167 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.171 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.171 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.176 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.176 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd', $2 = 'claim.name', $3 = 'zoneinfo'
docker-postgres-1  | 2023-12-03 09:25:11.181 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.181 UTC [219] DETAIL:  parameters: $1 = 'a0b00e40-49c1-4809-a24f-34804dcf57dd', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.183 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.183 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.185 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.185 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61', $2 = 'user.attribute', $3 = 'locale'
docker-postgres-1  | 2023-12-03 09:25:11.188 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.188 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.193 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.193 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.197 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.197 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61', $2 = 'claim.name', $3 = 'locale'
docker-postgres-1  | 2023-12-03 09:25:11.199 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.199 UTC [219] DETAIL:  parameters: $1 = 'ad100a61-5299-41f1-9303-e9021b36cf61', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.200 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.200 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.201 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.201 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb', $2 = 'user.attribute', $3 = 'gender'
docker-postgres-1  | 2023-12-03 09:25:11.204 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.204 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.208 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.208 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.209 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.209 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb', $2 = 'claim.name', $3 = 'gender'
docker-postgres-1  | 2023-12-03 09:25:11.210 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.210 UTC [219] DETAIL:  parameters: $1 = 'c8c21225-23c9-4959-b193-09bfdf24f0bb', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.211 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.211 UTC [219] DETAIL:  parameters: $1 = 'c9ca7c23-8659-47b7-a420-84e344ce69e6', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.216 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.216 UTC [219] DETAIL:  parameters: $1 = 'c9ca7c23-8659-47b7-a420-84e344ce69e6', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.218 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.218 UTC [219] DETAIL:  parameters: $1 = 'c9ca7c23-8659-47b7-a420-84e344ce69e6', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.220 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.220 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.222 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.222 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050', $2 = 'user.attribute', $3 = 'picture'
docker-postgres-1  | 2023-12-03 09:25:11.228 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.228 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.231 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.231 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.233 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.233 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050', $2 = 'claim.name', $3 = 'picture'
docker-postgres-1  | 2023-12-03 09:25:11.236 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.236 UTC [219] DETAIL:  parameters: $1 = 'cf874a93-0550-4e34-aecc-7a1ce92b2050', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.240 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.240 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.243 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.243 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d', $2 = 'user.attribute', $3 = 'nickname'
docker-postgres-1  | 2023-12-03 09:25:11.247 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.247 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.249 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.249 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.250 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.250 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d', $2 = 'claim.name', $3 = 'nickname'
docker-postgres-1  | 2023-12-03 09:25:11.253 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.253 UTC [219] DETAIL:  parameters: $1 = 'f6bd948e-43b7-4b64-902f-ebb05db5da8d', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.265 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.265 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.266 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.266 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418', $2 = 'user.attribute', $3 = 'website'
docker-postgres-1  | 2023-12-03 09:25:11.267 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.267 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.275 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.275 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.276 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.276 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418', $2 = 'claim.name', $3 = 'website'
docker-postgres-1  | 2023-12-03 09:25:11.277 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.277 UTC [219] DETAIL:  parameters: $1 = 'fdcc6f7f-ca85-4e57-8475-643bcb6fd418', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.311 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.311 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:11.315 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.315 UTC [219] DETAIL:  parameters: $1 = '${emailScopeConsentText}', $2 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:11.317 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.317 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:11.320 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.320 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428', $3 = 'email', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37'
docker-postgres-1  | 2023-12-03 09:25:11.322 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.322 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428', $3 = 'email verified', $4 = 'openid-connect', $5 = 'oidc-usermodel-property-mapper', $6 = '425d4268-f209-48b9-b9be-c647e563c8c1'
docker-postgres-1  | 2023-12-03 09:25:11.325 UTC [219] LOG:  execute S_19: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:11.325 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'address', $3 = NULL, $4 = 'fkh-customers-sample', $5 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:11.330 UTC [219] LOG:  execute <unnamed>: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:11.330 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect built-in scope: email', $2 = 'email', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:11.338 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.338 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.340 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.340 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37', $2 = 'user.attribute', $3 = 'email'
docker-postgres-1  | 2023-12-03 09:25:11.345 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.345 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.357 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.357 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.360 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.360 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37', $2 = 'claim.name', $3 = 'email'
docker-postgres-1  | 2023-12-03 09:25:11.362 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.362 UTC [219] DETAIL:  parameters: $1 = '3a7b5222-6da7-4ae5-978e-8f00f58e2c37', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.363 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.363 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.364 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.364 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1', $2 = 'user.attribute', $3 = 'emailVerified'
docker-postgres-1  | 2023-12-03 09:25:11.365 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.365 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.367 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.367 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.370 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.370 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1', $2 = 'claim.name', $3 = 'email_verified'
docker-postgres-1  | 2023-12-03 09:25:11.373 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.373 UTC [219] DETAIL:  parameters: $1 = '425d4268-f209-48b9-b9be-c647e563c8c1', $2 = 'jsonType.label', $3 = 'boolean'
docker-postgres-1  | 2023-12-03 09:25:11.388 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.388 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = '37dfba38-c780-486d-9634-ca3b452b4cf6', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:11.390 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.390 UTC [219] DETAIL:  parameters: $1 = '${addressScopeConsentText}', $2 = '37dfba38-c780-486d-9634-ca3b452b4cf6', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:11.406 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.406 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = '37dfba38-c780-486d-9634-ca3b452b4cf6', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:11.409 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.409 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '37dfba38-c780-486d-9634-ca3b452b4cf6', $3 = 'address', $4 = 'openid-connect', $5 = 'oidc-address-mapper', $6 = '96419e92-59bd-4aeb-b06a-8e6af64728dc'
docker-postgres-1  | 2023-12-03 09:25:11.411 UTC [219] LOG:  execute S_19: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:11.411 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'phone', $3 = NULL, $4 = 'fkh-customers-sample', $5 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:11.414 UTC [219] LOG:  execute S_20: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:11.414 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect built-in scope: address', $2 = 'address', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:11.416 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.416 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'user.attribute.formatted', $3 = 'formatted'
docker-postgres-1  | 2023-12-03 09:25:11.418 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.418 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'user.attribute.country', $3 = 'country'
docker-postgres-1  | 2023-12-03 09:25:11.420 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.420 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'user.attribute.postal_code', $3 = 'postal_code'
docker-postgres-1  | 2023-12-03 09:25:11.425 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.425 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.429 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.429 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'user.attribute.street', $3 = 'street'
docker-postgres-1  | 2023-12-03 09:25:11.431 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.431 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.432 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.432 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'user.attribute.region', $3 = 'region'
docker-postgres-1  | 2023-12-03 09:25:11.435 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.435 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.437 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.437 UTC [219] DETAIL:  parameters: $1 = '96419e92-59bd-4aeb-b06a-8e6af64728dc', $2 = 'user.attribute.locality', $3 = 'locality'
docker-postgres-1  | 2023-12-03 09:25:11.471 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.471 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'd4a865d8-4502-48c4-8f2f-47e432f40655', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:11.473 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.473 UTC [219] DETAIL:  parameters: $1 = '${phoneScopeConsentText}', $2 = 'd4a865d8-4502-48c4-8f2f-47e432f40655', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:11.491 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.491 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'd4a865d8-4502-48c4-8f2f-47e432f40655', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:11.497 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.497 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'd4a865d8-4502-48c4-8f2f-47e432f40655', $3 = 'phone number', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '263f56ef-a58c-4c57-a549-be7255d2533c'
docker-postgres-1  | 2023-12-03 09:25:11.499 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.499 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'd4a865d8-4502-48c4-8f2f-47e432f40655', $3 = 'phone number verified', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '1dc594bc-8c10-40a3-a605-ba379f105d36'
docker-postgres-1  | 2023-12-03 09:25:11.501 UTC [219] LOG:  execute <unnamed>: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.501 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '893ea2d3-b9a1-437a-a52c-ebe04746878f', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.505 UTC [219] LOG:  execute S_20: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:11.505 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect built-in scope: phone', $2 = 'phone', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:11.509 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.509 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.516 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.516 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36', $2 = 'user.attribute', $3 = 'phoneNumberVerified'
docker-postgres-1  | 2023-12-03 09:25:11.518 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.518 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.521 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.521 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.523 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.523 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36', $2 = 'claim.name', $3 = 'phone_number_verified'
docker-postgres-1  | 2023-12-03 09:25:11.526 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.526 UTC [219] DETAIL:  parameters: $1 = '1dc594bc-8c10-40a3-a605-ba379f105d36', $2 = 'jsonType.label', $3 = 'boolean'
docker-postgres-1  | 2023-12-03 09:25:11.532 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.532 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.537 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.537 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c', $2 = 'user.attribute', $3 = 'phoneNumber'
docker-postgres-1  | 2023-12-03 09:25:11.546 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.546 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.548 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.548 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.551 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.551 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c', $2 = 'claim.name', $3 = 'phone_number'
docker-postgres-1  | 2023-12-03 09:25:11.553 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.553 UTC [219] DETAIL:  parameters: $1 = '263f56ef-a58c-4c57-a549-be7255d2533c', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.577 UTC [219] LOG:  execute <unnamed>: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.577 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.604 UTC [219] LOG:  execute S_21: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.604 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '37dfba38-c780-486d-9634-ca3b452b4cf6', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.623 UTC [219] LOG:  execute S_21: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.623 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'd4a865d8-4502-48c4-8f2f-47e432f40655', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.634 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:11.634 UTC [219] DETAIL:  parameters: $1 = 'offline_access', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.653 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT_SCOPE c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:25:11.653 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.661 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT_SCOPE c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:25:11.661 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.684 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:11.684 UTC [219] DETAIL:  parameters: $1 = 'roles', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.714 UTC [219] LOG:  execute S_19: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:11.714 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'roles', $3 = NULL, $4 = 'fkh-customers-sample', $5 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:11.747 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.747 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:11.750 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.750 UTC [219] DETAIL:  parameters: $1 = '${rolesScopeConsentText}', $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:11.753 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.753 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:11.756 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.756 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'realm roles', $4 = 'openid-connect', $5 = 'oidc-usermodel-realm-role-mapper', $6 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f'
docker-postgres-1  | 2023-12-03 09:25:11.762 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.762 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'client roles', $4 = 'openid-connect', $5 = 'oidc-usermodel-client-role-mapper', $6 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6'
docker-postgres-1  | 2023-12-03 09:25:11.764 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.764 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'audience resolve', $4 = 'openid-connect', $5 = 'oidc-audience-resolve-mapper', $6 = '85fc98b4-f737-447b-8fe8-16b46bc16d6c'
docker-postgres-1  | 2023-12-03 09:25:11.767 UTC [219] LOG:  execute S_21: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.767 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.770 UTC [219] LOG:  execute S_20: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:11.770 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect scope for add user roles to the access token', $2 = 'roles', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:11.773 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.773 UTC [219] DETAIL:  parameters: $1 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f', $2 = 'multivalued', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.777 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.777 UTC [219] DETAIL:  parameters: $1 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f', $2 = 'user.attribute', $3 = 'foo'
docker-postgres-1  | 2023-12-03 09:25:11.780 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.780 UTC [219] DETAIL:  parameters: $1 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.782 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.782 UTC [219] DETAIL:  parameters: $1 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f', $2 = 'claim.name', $3 = 'realm_access.roles'
docker-postgres-1  | 2023-12-03 09:25:11.796 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.796 UTC [219] DETAIL:  parameters: $1 = '9ac54b2d-d15f-4b49-b4b6-dd80ca9c2b9f', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.799 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.799 UTC [219] DETAIL:  parameters: $1 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6', $2 = 'multivalued', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.803 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.803 UTC [219] DETAIL:  parameters: $1 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6', $2 = 'user.attribute', $3 = 'foo'
docker-postgres-1  | 2023-12-03 09:25:11.805 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.805 UTC [219] DETAIL:  parameters: $1 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:11.809 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.809 UTC [219] DETAIL:  parameters: $1 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6', $2 = 'claim.name', $3 = 'resource_access.${client_id}.roles'
docker-postgres-1  | 2023-12-03 09:25:11.819 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.819 UTC [219] DETAIL:  parameters: $1 = 'afe17e6a-7d40-4abf-a440-708ea1d814e6', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:11.830 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT_SCOPE c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:25:11.830 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.854 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:11.854 UTC [219] DETAIL:  parameters: $1 = 'web-origins', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.864 UTC [219] LOG:  execute S_19: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:11.864 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'web-origins', $3 = NULL, $4 = 'fkh-customers-sample', $5 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:11.896 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.896 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = '8707c208-8f4f-4fc5-99ad-b8847237e499', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:11.900 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.900 UTC [219] DETAIL:  parameters: $1 = '', $2 = '8707c208-8f4f-4fc5-99ad-b8847237e499', $3 = 'consent.screen.text'
docker-postgres-1  | 2023-12-03 09:25:11.905 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.905 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = '8707c208-8f4f-4fc5-99ad-b8847237e499', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:11.909 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:11.909 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = '8707c208-8f4f-4fc5-99ad-b8847237e499', $3 = 'allowed web origins', $4 = 'openid-connect', $5 = 'oidc-allowed-origins-mapper', $6 = '363d81b3-966c-465c-a376-b350cc0fffde'
docker-postgres-1  | 2023-12-03 09:25:11.913 UTC [219] LOG:  execute S_21: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.913 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '8707c208-8f4f-4fc5-99ad-b8847237e499', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.918 UTC [219] LOG:  execute S_20: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:11.918 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect scope for add allowed web origins to the access token', $2 = 'web-origins', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:11.932 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT_SCOPE c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:25:11.932 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.957 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:11.957 UTC [219] DETAIL:  parameters: $1 = 'microprofile-jwt', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:11.984 UTC [219] LOG:  execute S_19: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:11.984 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'microprofile-jwt', $3 = NULL, $4 = 'fkh-customers-sample', $5 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:11.998 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:11.998 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:12.001 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.001 UTC [219] DETAIL:  parameters: $1 = 'true', $2 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:12.016 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:12.016 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29', $3 = 'upn', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d'
docker-postgres-1  | 2023-12-03 09:25:12.020 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:12.020 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29', $3 = 'groups', $4 = 'openid-connect', $5 = 'oidc-usermodel-realm-role-mapper', $6 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4'
docker-postgres-1  | 2023-12-03 09:25:12.023 UTC [219] LOG:  execute S_21: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.023 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:12.026 UTC [219] LOG:  execute S_20: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:12.026 UTC [219] DETAIL:  parameters: $1 = 'Microprofile - JWT built-in scope', $2 = 'microprofile-jwt', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:12.028 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.028 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.030 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.030 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d', $2 = 'user.attribute', $3 = 'username'
docker-postgres-1  | 2023-12-03 09:25:12.032 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.032 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.034 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.034 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.038 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.038 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d', $2 = 'claim.name', $3 = 'upn'
docker-postgres-1  | 2023-12-03 09:25:12.042 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.042 UTC [219] DETAIL:  parameters: $1 = 'c7c4ccc4-698f-4e9f-860d-110a49515e5d', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:12.044 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.044 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4', $2 = 'multivalued', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.047 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.047 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4', $2 = 'user.attribute', $3 = 'foo'
docker-postgres-1  | 2023-12-03 09:25:12.049 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.049 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.052 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.052 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.056 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.056 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4', $2 = 'claim.name', $3 = 'groups'
docker-postgres-1  | 2023-12-03 09:25:12.060 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.060 UTC [219] DETAIL:  parameters: $1 = 'f32584a3-627f-4ee4-8b4f-eed7d025dfe4', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:12.067 UTC [219] LOG:  execute S_22: select c1_0.ID from CLIENT_SCOPE c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:25:12.067 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:12.098 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:12.098 UTC [219] DETAIL:  parameters: $1 = 'acr', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:12.136 UTC [219] LOG:  execute S_19: insert into CLIENT_SCOPE (DESCRIPTION,NAME,PROTOCOL,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:12.136 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'acr', $3 = NULL, $4 = 'fkh-customers-sample', $5 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:12.149 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.149 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'b715d149-2769-4200-8712-65d6da541e80', $3 = 'display.on.consent.screen'
docker-postgres-1  | 2023-12-03 09:25:12.165 UTC [219] LOG:  execute S_16: insert into CLIENT_SCOPE_ATTRIBUTES (VALUE,SCOPE_ID,NAME) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.165 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'b715d149-2769-4200-8712-65d6da541e80', $3 = 'include.in.token.scope'
docker-postgres-1  | 2023-12-03 09:25:12.167 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:12.167 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'b715d149-2769-4200-8712-65d6da541e80', $3 = 'acr loa level', $4 = 'openid-connect', $5 = 'oidc-acr-mapper', $6 = '8a4d80da-9a87-4a54-b5f6-bee7fd3534d8'
docker-postgres-1  | 2023-12-03 09:25:12.172 UTC [219] LOG:  execute S_21: insert into DEFAULT_CLIENT_SCOPE (DEFAULT_SCOPE,SCOPE_ID,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.172 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'b715d149-2769-4200-8712-65d6da541e80', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:12.186 UTC [219] LOG:  execute S_20: update CLIENT_SCOPE set DESCRIPTION=$1,NAME=$2,PROTOCOL=$3,REALM_ID=$4 where ID=$5
docker-postgres-1  | 2023-12-03 09:25:12.186 UTC [219] DETAIL:  parameters: $1 = 'OpenID Connect scope for add acr (authentication context class reference) to the token', $2 = 'acr', $3 = 'openid-connect', $4 = 'fkh-customers-sample', $5 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:12.189 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.189 UTC [219] DETAIL:  parameters: $1 = '8a4d80da-9a87-4a54-b5f6-bee7fd3534d8', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.191 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.191 UTC [219] DETAIL:  parameters: $1 = '8a4d80da-9a87-4a54-b5f6-bee7fd3534d8', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:12.213 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.213 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.219 UTC [219] LOG:  execute S_9: select d1_0.SCOPE_ID from DEFAULT_CLIENT_SCOPE d1_0 where d1_0.REALM_ID=$1 and d1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.219 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.261 UTC [219] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.REALM_ID=$1 order by c1_0.CLIENT_ID
docker-postgres-1  | 2023-12-03 09:25:12.261 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:12.275 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.275 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.287 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.287 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.296 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.296 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:12.316 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.316 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:12.330 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.330 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:12.347 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.347 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:12.365 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.365 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:12.379 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.379 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.396 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.396 UTC [219] DETAIL:  parameters: $1 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.409 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.409 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:12.433 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.433 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:12.459 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.459 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:12.493 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.493 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2', $3 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:12.519 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.519 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.539 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.539 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.548 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.548 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:12.570 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.570 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:12.581 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.581 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:12.602 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.602 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:12.620 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.620 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:12.627 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.627 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.654 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.654 UTC [219] DETAIL:  parameters: $1 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.679 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.679 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:12.693 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.693 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:12.697 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.697 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:12.711 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.711 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '5229c301-fe3e-493c-b403-c5ca1ee4e579', $3 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:12.729 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.729 UTC [219] DETAIL:  parameters: $1 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.733 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.733 UTC [219] DETAIL:  parameters: $1 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.746 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.746 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:12.758 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.758 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:12.772 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.772 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:12.782 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.782 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:12.799 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.799 UTC [219] DETAIL:  parameters: $1 = 't', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:12.816 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.816 UTC [219] DETAIL:  parameters: $1 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.831 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.831 UTC [219] DETAIL:  parameters: $1 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.838 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.838 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:12.845 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.845 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:12.850 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.850 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:12.859 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.859 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'a3600a59-5c16-48e2-869e-8d6e16fc9028', $3 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:12.870 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.870 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.877 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.877 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.886 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.886 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:12.898 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.898 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:12.907 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.907 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:12.914 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.914 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:12.923 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.923 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:12.928 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.928 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:12.937 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.937 UTC [219] DETAIL:  parameters: $1 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:12.945 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.945 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:12.958 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.958 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:12.964 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.964 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:12.988 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:12.988 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '23e4beff-5d1c-4712-abaa-3b9f6a4c2567', $3 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:12.997 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:12.997 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:13.003 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.003 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:13.008 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.008 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:13.029 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.029 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:13.036 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.036 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:13.041 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.041 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:13.051 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.051 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:13.071 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.071 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:13.077 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.077 UTC [219] DETAIL:  parameters: $1 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:13.086 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.086 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:13.098 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.098 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:13.110 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.110 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:13.121 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.121 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '7e65e81d-3a62-40d9-acf8-799fb7f26518', $3 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:13.131 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.131 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:13.142 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.142 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:13.152 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.152 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = '893ea2d3-b9a1-437a-a52c-ebe04746878f'
docker-postgres-1  | 2023-12-03 09:25:13.170 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.170 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'f5dd57f9-ac8a-49a9-a794-d5f986f22428'
docker-postgres-1  | 2023-12-03 09:25:13.189 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.189 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'ba8e6f42-5062-4c57-8c4b-dbd7b499eb82'
docker-postgres-1  | 2023-12-03 09:25:13.195 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.195 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'b715d149-2769-4200-8712-65d6da541e80'
docker-postgres-1  | 2023-12-03 09:25:13.209 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.209 UTC [219] DETAIL:  parameters: $1 = 't', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = '8707c208-8f4f-4fc5-99ad-b8847237e499'
docker-postgres-1  | 2023-12-03 09:25:13.217 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.217 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = 't'
docker-postgres-1  | 2023-12-03 09:25:13.227 UTC [219] LOG:  execute S_15: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-03 09:25:13.227 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = 'f'
docker-postgres-1  | 2023-12-03 09:25:13.233 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.233 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = '37dfba38-c780-486d-9634-ca3b452b4cf6'
docker-postgres-1  | 2023-12-03 09:25:13.243 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.243 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'faaa30fa-926c-4eb4-be7d-2a1de56adb29'
docker-postgres-1  | 2023-12-03 09:25:13.257 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.257 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'e317c170-bc1d-4476-9a32-15ae2aa3d422'
docker-postgres-1  | 2023-12-03 09:25:13.274 UTC [219] LOG:  execute S_23: insert into CLIENT_SCOPE_CLIENT (DEFAULT_SCOPE,CLIENT_ID,SCOPE_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.274 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = '63310b6e-7601-42ce-86a9-b008c64c019d', $3 = 'd4a865d8-4502-48c4-8f2f-47e432f40655'
docker-postgres-1  | 2023-12-03 09:25:13.298 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:13.298 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '0', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 't', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.336 UTC [219] LOG:  execute <unnamed>: delete from REALM_EVENTS_LISTENERS where REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:25:13.336 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.345 UTC [219] LOG:  execute <unnamed>: insert into REALM_EVENTS_LISTENERS (REALM_ID,VALUE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:13.345 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample', $2 = 'jboss-logging'
docker-postgres-1  | 2023-12-03 09:25:13.375 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.375 UTC [219] DETAIL:  parameters: $1 = 'RS256', $2 = 'defaultSignatureAlgorithm', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.379 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:13.379 UTC [219] DETAIL:  parameters: $1 = '0', $2 = '0', $3 = '0', $4 = '300', $5 = '0', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 't', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '0', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '0', $47 = '0', $48 = '0', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.389 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.389 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'offlineSessionMaxLifespanEnabled', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.392 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.392 UTC [219] DETAIL:  parameters: $1 = '5184000', $2 = 'offlineSessionMaxLifespan', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.394 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.394 UTC [219] DETAIL:  parameters: $1 = '0', $2 = 'clientSessionIdleTimeout', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.396 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.396 UTC [219] DETAIL:  parameters: $1 = '0', $2 = 'clientSessionMaxLifespan', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.400 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:13.400 UTC [219] DETAIL:  parameters: $1 = '60', $2 = '0', $3 = '0', $4 = '300', $5 = '900', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 't', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '2592000', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '1800', $47 = '0', $48 = '36000', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.408 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:13.408 UTC [219] DETAIL:  parameters: $1 = '60', $2 = '0', $3 = '300', $4 = '300', $5 = '900', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 't', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '2592000', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '1800', $47 = '0', $48 = '36000', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.414 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:13.414 UTC [219] DETAIL:  parameters: $1 = '60', $2 = '1800', $3 = '300', $4 = '300', $5 = '900', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = NULL, $12 = NULL, $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = NULL, $16 = NULL, $17 = 'f', $18 = 'f', $19 = NULL, $20 = 't', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '2592000', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = NULL, $41 = 'f', $42 = NULL, $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '1800', $47 = '0', $48 = '36000', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.423 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.423 UTC [219] DETAIL:  parameters: $1 = '43200', $2 = 'actionTokenGeneratedByAdminLifespan', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.425 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.425 UTC [219] DETAIL:  parameters: $1 = '300', $2 = 'actionTokenGeneratedByUserLifespan', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.426 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.426 UTC [219] DETAIL:  parameters: $1 = '600', $2 = 'oauth2DeviceCodeLifespan', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.428 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.428 UTC [219] DETAIL:  parameters: $1 = '5', $2 = 'oauth2DevicePollingInterval', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.462 UTC [219] LOG:  execute <unnamed>: insert into REALM_REQUIRED_CREDENTIAL (FORM_LABEL,INPUT,SECRET,REALM_ID,TYPE) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:13.462 UTC [219] DETAIL:  parameters: $1 = 'password', $2 = 't', $3 = 't', $4 = 'fkh-customers-sample', $5 = 'password'
docker-postgres-1  | 2023-12-03 09:25:13.533 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.533 UTC [219] DETAIL:  parameters: $1 = 'keycloak', $2 = 'webAuthnPolicyRpEntityName', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.535 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.535 UTC [219] DETAIL:  parameters: $1 = 'ES256', $2 = 'webAuthnPolicySignatureAlgorithms', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.537 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.537 UTC [219] DETAIL:  parameters: $1 = '', $2 = 'webAuthnPolicyRpId', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.540 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.540 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyAttestationConveyancePreference', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.542 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.542 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyAuthenticatorAttachment', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.549 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.549 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyRequireResidentKey', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.555 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.555 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyUserVerificationRequirement', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.558 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.558 UTC [219] DETAIL:  parameters: $1 = '0', $2 = 'webAuthnPolicyCreateTimeout', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.560 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.560 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'webAuthnPolicyAvoidSameAuthenticatorRegister', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.562 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.562 UTC [219] DETAIL:  parameters: $1 = 'keycloak', $2 = 'webAuthnPolicyRpEntityNamePasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.564 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.564 UTC [219] DETAIL:  parameters: $1 = 'ES256', $2 = 'webAuthnPolicySignatureAlgorithmsPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.565 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.565 UTC [219] DETAIL:  parameters: $1 = '', $2 = 'webAuthnPolicyRpIdPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.566 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.566 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyAttestationConveyancePreferencePasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.567 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.567 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyAuthenticatorAttachmentPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.570 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.570 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyRequireResidentKeyPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.574 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.574 UTC [219] DETAIL:  parameters: $1 = 'not specified', $2 = 'webAuthnPolicyUserVerificationRequirementPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.576 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.576 UTC [219] DETAIL:  parameters: $1 = '0', $2 = 'webAuthnPolicyCreateTimeoutPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.578 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.578 UTC [219] DETAIL:  parameters: $1 = 'false', $2 = 'webAuthnPolicyAvoidSameAuthenticatorRegisterPasswordless', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.579 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.579 UTC [219] DETAIL:  parameters: $1 = 'poll', $2 = 'cibaBackchannelTokenDeliveryMode', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.580 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.580 UTC [219] DETAIL:  parameters: $1 = '120', $2 = 'cibaExpiresIn', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.582 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.582 UTC [219] DETAIL:  parameters: $1 = '5', $2 = 'cibaInterval', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.591 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.591 UTC [219] DETAIL:  parameters: $1 = 'login_hint', $2 = 'cibaAuthRequestedUserHint', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.595 UTC [219] LOG:  execute S_3: insert into REALM_ATTRIBUTE (VALUE,NAME,REALM_ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.595 UTC [219] DETAIL:  parameters: $1 = '60', $2 = 'parRequestUriLifespan', $3 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.597 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.597 UTC [219] DETAIL:  parameters: $1 = 'browser', $2 = 't', $3 = 'browser based authentication', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = '0778f648-540f-41af-8719-e7f0fac82fef'
docker-postgres-1  | 2023-12-03 09:25:13.599 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.599 UTC [219] DETAIL:  parameters: $1 = 'auth-cookie', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0778f648-540f-41af-8719-e7f0fac82fef', $6 = '10', $7 = 'fkh-customers-sample', $8 = '2', $9 = '0bc3729c-9b3e-4993-bec9-a312294e9547'
docker-postgres-1  | 2023-12-03 09:25:13.603 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.603 UTC [219] DETAIL:  parameters: $1 = 'auth-spnego', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0778f648-540f-41af-8719-e7f0fac82fef', $6 = '20', $7 = 'fkh-customers-sample', $8 = '3', $9 = 'b14dfb60-62e0-4810-95e6-d96d6b999fa7'
docker-postgres-1  | 2023-12-03 09:25:13.607 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.607 UTC [219] DETAIL:  parameters: $1 = 'identity-provider-redirector', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0778f648-540f-41af-8719-e7f0fac82fef', $6 = '25', $7 = 'fkh-customers-sample', $8 = '2', $9 = 'b578eed7-d81f-4b35-8275-d3fb6b7181fa'
docker-postgres-1  | 2023-12-03 09:25:13.609 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.609 UTC [219] DETAIL:  parameters: $1 = 'forms', $2 = 't', $3 = 'Username, password, otp and other auth forms.', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = '8e4e4c1d-4bfc-44c2-aeea-2dd9d68ec00d'
docker-postgres-1  | 2023-12-03 09:25:13.610 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.610 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = '8e4e4c1d-4bfc-44c2-aeea-2dd9d68ec00d', $5 = '0778f648-540f-41af-8719-e7f0fac82fef', $6 = '30', $7 = 'fkh-customers-sample', $8 = '2', $9 = '32aad481-8a37-4463-a720-b8e73e712188'
docker-postgres-1  | 2023-12-03 09:25:13.611 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.611 UTC [219] DETAIL:  parameters: $1 = 'auth-username-password-form', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '8e4e4c1d-4bfc-44c2-aeea-2dd9d68ec00d', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'feb5cbec-d83c-46ba-bd27-79756e8fc7e2'
docker-postgres-1  | 2023-12-03 09:25:13.613 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.613 UTC [219] DETAIL:  parameters: $1 = 'Browser - Conditional OTP', $2 = 't', $3 = 'Flow to determine if the OTP is required for the authentication', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = '9bd05224-0426-4238-9206-08c655d4861d'
docker-postgres-1  | 2023-12-03 09:25:13.613 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.613 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = '9bd05224-0426-4238-9206-08c655d4861d', $5 = '8e4e4c1d-4bfc-44c2-aeea-2dd9d68ec00d', $6 = '20', $7 = 'fkh-customers-sample', $8 = '1', $9 = 'df012500-5b7a-4e65-b93c-e7782423a5fa'
docker-postgres-1  | 2023-12-03 09:25:13.614 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.614 UTC [219] DETAIL:  parameters: $1 = 'conditional-user-configured', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '9bd05224-0426-4238-9206-08c655d4861d', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'c7aca3cc-da8a-4cd4-b41d-82127f3b0bc9'
docker-postgres-1  | 2023-12-03 09:25:13.616 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.616 UTC [219] DETAIL:  parameters: $1 = 'auth-otp-form', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '9bd05224-0426-4238-9206-08c655d4861d', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'c3f42867-db9c-4a50-a33a-b4ac332489dd'
docker-postgres-1  | 2023-12-03 09:25:13.617 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.617 UTC [219] DETAIL:  parameters: $1 = 'direct grant', $2 = 't', $3 = 'OpenID Connect Resource Owner Grant', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = '4599507d-63cd-4d28-a696-3513bc2ffd18'
docker-postgres-1  | 2023-12-03 09:25:13.618 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.618 UTC [219] DETAIL:  parameters: $1 = 'direct-grant-validate-username', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '4599507d-63cd-4d28-a696-3513bc2ffd18', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '46f09a80-db07-4575-81db-d65e371b2965'
docker-postgres-1  | 2023-12-03 09:25:13.620 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.620 UTC [219] DETAIL:  parameters: $1 = 'direct-grant-validate-password', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '4599507d-63cd-4d28-a696-3513bc2ffd18', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'd314169b-69b4-4cda-870e-1a496375a98e'
docker-postgres-1  | 2023-12-03 09:25:13.621 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.621 UTC [219] DETAIL:  parameters: $1 = 'Direct Grant - Conditional OTP', $2 = 't', $3 = 'Flow to determine if the OTP is required for the authentication', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = '218adc84-d74b-4a97-9100-369ccf920ade'
docker-postgres-1  | 2023-12-03 09:25:13.624 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.624 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = '218adc84-d74b-4a97-9100-369ccf920ade', $5 = '4599507d-63cd-4d28-a696-3513bc2ffd18', $6 = '30', $7 = 'fkh-customers-sample', $8 = '1', $9 = '58c759d2-870a-4bbb-9787-88ec58749eaf'
docker-postgres-1  | 2023-12-03 09:25:13.632 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.632 UTC [219] DETAIL:  parameters: $1 = 'conditional-user-configured', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '218adc84-d74b-4a97-9100-369ccf920ade', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'cc46ee27-c0b5-4c67-abc4-ce00703672e2'
docker-postgres-1  | 2023-12-03 09:25:13.636 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.636 UTC [219] DETAIL:  parameters: $1 = 'direct-grant-validate-otp', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '218adc84-d74b-4a97-9100-369ccf920ade', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = '556ab4cd-8d68-4f9e-bcf9-49cf8fe86255'
docker-postgres-1  | 2023-12-03 09:25:13.641 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.641 UTC [219] DETAIL:  parameters: $1 = 'registration', $2 = 't', $3 = 'registration flow', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = 'e27bc65f-e3aa-44d0-8c07-e1254088b71c'
docker-postgres-1  | 2023-12-03 09:25:13.642 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.642 UTC [219] DETAIL:  parameters: $1 = 'registration form', $2 = 't', $3 = 'registration form', $4 = 'form-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = '0b220305-7b56-4f05-8d38-666360f53569'
docker-postgres-1  | 2023-12-03 09:25:13.643 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.643 UTC [219] DETAIL:  parameters: $1 = 'registration-page-form', $2 = NULL, $3 = 't', $4 = '0b220305-7b56-4f05-8d38-666360f53569', $5 = 'e27bc65f-e3aa-44d0-8c07-e1254088b71c', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '8f0130af-1183-4ea6-b5ac-3e195504b427'
docker-postgres-1  | 2023-12-03 09:25:13.644 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.644 UTC [219] DETAIL:  parameters: $1 = 'registration-user-creation', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0b220305-7b56-4f05-8d38-666360f53569', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'f08ec2dd-3a92-45a4-8523-7707a3773227'
docker-postgres-1  | 2023-12-03 09:25:13.645 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.645 UTC [219] DETAIL:  parameters: $1 = 'registration-profile-action', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0b220305-7b56-4f05-8d38-666360f53569', $6 = '40', $7 = 'fkh-customers-sample', $8 = '0', $9 = '60107a08-89d4-4983-8406-445b78533f64'
docker-postgres-1  | 2023-12-03 09:25:13.646 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.646 UTC [219] DETAIL:  parameters: $1 = 'registration-password-action', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0b220305-7b56-4f05-8d38-666360f53569', $6 = '50', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'f0ed08fc-03e8-4f61-968d-5e70f3186c24'
docker-postgres-1  | 2023-12-03 09:25:13.647 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.647 UTC [219] DETAIL:  parameters: $1 = 'registration-recaptcha-action', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '0b220305-7b56-4f05-8d38-666360f53569', $6 = '60', $7 = 'fkh-customers-sample', $8 = '3', $9 = '21d3e4fb-6201-45a3-9835-59bcab7e48ff'
docker-postgres-1  | 2023-12-03 09:25:13.647 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.647 UTC [219] DETAIL:  parameters: $1 = 'reset credentials', $2 = 't', $3 = 'Reset credentials for a user if they forgot their password or something', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = '3c8bd7f1-babd-414a-bb3d-d15658d44550'
docker-postgres-1  | 2023-12-03 09:25:13.648 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.648 UTC [219] DETAIL:  parameters: $1 = 'reset-credentials-choose-user', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '3c8bd7f1-babd-414a-bb3d-d15658d44550', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '009fc808-55b8-46a8-b1e8-63d340bd346e'
docker-postgres-1  | 2023-12-03 09:25:13.651 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.651 UTC [219] DETAIL:  parameters: $1 = 'reset-credential-email', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '3c8bd7f1-babd-414a-bb3d-d15658d44550', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = '7b71819d-869c-49ef-95cb-dc56549600b8'
docker-postgres-1  | 2023-12-03 09:25:13.655 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.655 UTC [219] DETAIL:  parameters: $1 = 'reset-password', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '3c8bd7f1-babd-414a-bb3d-d15658d44550', $6 = '30', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'd0272216-7ec4-4ae1-a67b-d811f59f6928'
docker-postgres-1  | 2023-12-03 09:25:13.657 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.657 UTC [219] DETAIL:  parameters: $1 = 'Reset - Conditional OTP', $2 = 't', $3 = 'Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = 'c9289271-299d-427f-b5ff-8ea41dad7a2d'
docker-postgres-1  | 2023-12-03 09:25:13.659 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.659 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = 'c9289271-299d-427f-b5ff-8ea41dad7a2d', $5 = '3c8bd7f1-babd-414a-bb3d-d15658d44550', $6 = '40', $7 = 'fkh-customers-sample', $8 = '1', $9 = '3ede49a0-02d5-41ec-b4d8-6927cc9d58dc'
docker-postgres-1  | 2023-12-03 09:25:13.662 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.662 UTC [219] DETAIL:  parameters: $1 = 'conditional-user-configured', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'c9289271-299d-427f-b5ff-8ea41dad7a2d', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '6bee6eca-9f9a-4404-b199-30969604b34a'
docker-postgres-1  | 2023-12-03 09:25:13.666 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.666 UTC [219] DETAIL:  parameters: $1 = 'reset-otp', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'c9289271-299d-427f-b5ff-8ea41dad7a2d', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = '05581bfb-f0c6-484c-ab73-a4fbfc21863a'
docker-postgres-1  | 2023-12-03 09:25:13.667 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.667 UTC [219] DETAIL:  parameters: $1 = 'clients', $2 = 't', $3 = 'Base authentication for clients', $4 = 'client-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c'
docker-postgres-1  | 2023-12-03 09:25:13.669 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.669 UTC [219] DETAIL:  parameters: $1 = 'client-secret', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c', $6 = '10', $7 = 'fkh-customers-sample', $8 = '2', $9 = '4b4ea39e-4522-4c92-9abe-7cca33d7bf27'
docker-postgres-1  | 2023-12-03 09:25:13.671 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.671 UTC [219] DETAIL:  parameters: $1 = 'client-jwt', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c', $6 = '20', $7 = 'fkh-customers-sample', $8 = '2', $9 = '8556cc50-a681-4184-8668-e680cfc853a4'
docker-postgres-1  | 2023-12-03 09:25:13.673 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.673 UTC [219] DETAIL:  parameters: $1 = 'client-secret-jwt', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c', $6 = '30', $7 = 'fkh-customers-sample', $8 = '2', $9 = '3da58847-8679-41ae-8d5e-c48b2eb5d93b'
docker-postgres-1  | 2023-12-03 09:25:13.675 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.675 UTC [219] DETAIL:  parameters: $1 = 'client-x509', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c', $6 = '40', $7 = 'fkh-customers-sample', $8 = '2', $9 = 'dc087cc0-63a7-4009-95f3-3d223a94db83'
docker-postgres-1  | 2023-12-03 09:25:13.676 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.676 UTC [219] DETAIL:  parameters: $1 = 'first broker login', $2 = 't', $3 = 'Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = 'f97f67c2-6e15-42ea-a886-3907086513d7'
docker-postgres-1  | 2023-12-03 09:25:13.678 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATOR_CONFIG (ALIAS,REALM_ID,ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.678 UTC [219] DETAIL:  parameters: $1 = 'review profile config', $2 = 'fkh-customers-sample', $3 = '1c049043-b23a-4880-ac03-7a58b033d97f'
docker-postgres-1  | 2023-12-03 09:25:13.679 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.679 UTC [219] DETAIL:  parameters: $1 = 'idp-review-profile', $2 = '1c049043-b23a-4880-ac03-7a58b033d97f', $3 = 'f', $4 = NULL, $5 = 'f97f67c2-6e15-42ea-a886-3907086513d7', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'e02b5b49-1c8b-4a14-9119-f84eac997de3'
docker-postgres-1  | 2023-12-03 09:25:13.680 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.680 UTC [219] DETAIL:  parameters: $1 = 'User creation or linking', $2 = 't', $3 = 'Flow for the existing/non-existing user alternatives', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = '5e7b89e2-8925-4776-ab49-da6f7261ede8'
docker-postgres-1  | 2023-12-03 09:25:13.681 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.681 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = '5e7b89e2-8925-4776-ab49-da6f7261ede8', $5 = 'f97f67c2-6e15-42ea-a886-3907086513d7', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'eb0e9366-dd98-45d7-9be7-4b599b5736af'
docker-postgres-1  | 2023-12-03 09:25:13.682 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATOR_CONFIG (ALIAS,REALM_ID,ID) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.682 UTC [219] DETAIL:  parameters: $1 = 'create unique user config', $2 = 'fkh-customers-sample', $3 = '87b2aff3-0155-42c4-a5d3-63cb2e6e9778'
docker-postgres-1  | 2023-12-03 09:25:13.683 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.683 UTC [219] DETAIL:  parameters: $1 = 'idp-create-user-if-unique', $2 = '87b2aff3-0155-42c4-a5d3-63cb2e6e9778', $3 = 'f', $4 = NULL, $5 = '5e7b89e2-8925-4776-ab49-da6f7261ede8', $6 = '10', $7 = 'fkh-customers-sample', $8 = '2', $9 = '0082217b-f372-4f67-9beb-c0064a630bfc'
docker-postgres-1  | 2023-12-03 09:25:13.684 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.684 UTC [219] DETAIL:  parameters: $1 = 'Handle Existing Account', $2 = 't', $3 = 'Handle what to do if there is existing account with same email/username like authenticated identity provider', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = 'f6264b3f-7533-45e9-b4d1-068c60ce3be0'
docker-postgres-1  | 2023-12-03 09:25:13.686 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.686 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = 'f6264b3f-7533-45e9-b4d1-068c60ce3be0', $5 = '5e7b89e2-8925-4776-ab49-da6f7261ede8', $6 = '20', $7 = 'fkh-customers-sample', $8 = '2', $9 = '38ea9f99-9e97-481c-b41f-61b058fc003e'
docker-postgres-1  | 2023-12-03 09:25:13.687 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.687 UTC [219] DETAIL:  parameters: $1 = 'idp-confirm-link', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'f6264b3f-7533-45e9-b4d1-068c60ce3be0', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '7e25b524-440e-464c-ad7c-e149e05a2c6b'
docker-postgres-1  | 2023-12-03 09:25:13.690 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.690 UTC [219] DETAIL:  parameters: $1 = 'Account verification options', $2 = 't', $3 = 'Method with which to verity the existing account', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = 'e3bedd09-2b29-47bd-a79f-0bc1b0809e2a'
docker-postgres-1  | 2023-12-03 09:25:13.692 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.692 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = 'e3bedd09-2b29-47bd-a79f-0bc1b0809e2a', $5 = 'f6264b3f-7533-45e9-b4d1-068c60ce3be0', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'cd2ea5b2-2720-4064-a2a1-6048b900fbba'
docker-postgres-1  | 2023-12-03 09:25:13.694 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.694 UTC [219] DETAIL:  parameters: $1 = 'idp-email-verification', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'e3bedd09-2b29-47bd-a79f-0bc1b0809e2a', $6 = '10', $7 = 'fkh-customers-sample', $8 = '2', $9 = 'bd76a02e-f4e1-4fe4-a83e-3906f008001e'
docker-postgres-1  | 2023-12-03 09:25:13.697 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.697 UTC [219] DETAIL:  parameters: $1 = 'Verify Existing Account by Re-authentication', $2 = 't', $3 = 'Reauthentication of existing account', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = '3441899b-8687-4d25-9c5b-c82a7d2c5d99'
docker-postgres-1  | 2023-12-03 09:25:13.698 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.698 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = '3441899b-8687-4d25-9c5b-c82a7d2c5d99', $5 = 'e3bedd09-2b29-47bd-a79f-0bc1b0809e2a', $6 = '20', $7 = 'fkh-customers-sample', $8 = '2', $9 = '13606ed6-be70-489c-8840-0a0d34a0cc0b'
docker-postgres-1  | 2023-12-03 09:25:13.699 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.699 UTC [219] DETAIL:  parameters: $1 = 'idp-username-password-form', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '3441899b-8687-4d25-9c5b-c82a7d2c5d99', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '4767be83-7586-475d-8f5e-1a9327c91a86'
docker-postgres-1  | 2023-12-03 09:25:13.700 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.700 UTC [219] DETAIL:  parameters: $1 = 'First broker login - Conditional OTP', $2 = 't', $3 = 'Flow to determine if the OTP is required for the authentication', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 'f', $7 = 'e5eb8fe6-40b1-4a1b-b95a-d1a067b14780'
docker-postgres-1  | 2023-12-03 09:25:13.702 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.702 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = NULL, $3 = 't', $4 = 'e5eb8fe6-40b1-4a1b-b95a-d1a067b14780', $5 = '3441899b-8687-4d25-9c5b-c82a7d2c5d99', $6 = '20', $7 = 'fkh-customers-sample', $8 = '1', $9 = '2a6ec45b-35f8-4b27-b910-0a7488e3fecd'
docker-postgres-1  | 2023-12-03 09:25:13.703 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.703 UTC [219] DETAIL:  parameters: $1 = 'conditional-user-configured', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'e5eb8fe6-40b1-4a1b-b95a-d1a067b14780', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'cacb58e5-6bfe-496a-8ec3-b83b5500eb69'
docker-postgres-1  | 2023-12-03 09:25:13.705 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.705 UTC [219] DETAIL:  parameters: $1 = 'auth-otp-form', $2 = NULL, $3 = 'f', $4 = NULL, $5 = 'e5eb8fe6-40b1-4a1b-b95a-d1a067b14780', $6 = '20', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'afc2816a-8c1a-4aad-87fc-e515a438e66a'
docker-postgres-1  | 2023-12-03 09:25:13.707 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.707 UTC [219] DETAIL:  parameters: $1 = 'saml ecp', $2 = 't', $3 = 'SAML ECP Profile Authentication Flow', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = '6be71ae2-31ee-4758-8a20-c973e27d6afc'
docker-postgres-1  | 2023-12-03 09:25:13.708 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.708 UTC [219] DETAIL:  parameters: $1 = 'http-basic-authenticator', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '6be71ae2-31ee-4758-8a20-c973e27d6afc', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = 'ba06977d-db3f-4189-9ba8-829edbfafcc6'
docker-postgres-1  | 2023-12-03 09:25:13.709 UTC [219] LOG:  execute S_25: insert into AUTHENTICATION_FLOW (ALIAS,BUILT_IN,DESCRIPTION,PROVIDER_ID,REALM_ID,TOP_LEVEL,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.709 UTC [219] DETAIL:  parameters: $1 = 'docker auth', $2 = 't', $3 = 'Used by Docker clients to authenticate against the IDP', $4 = 'basic-flow', $5 = 'fkh-customers-sample', $6 = 't', $7 = '2f492243-f94b-4334-a13d-359c2fbe6031'
docker-postgres-1  | 2023-12-03 09:25:13.710 UTC [219] LOG:  execute S_24: insert into AUTHENTICATION_EXECUTION (AUTHENTICATOR,AUTH_CONFIG,AUTHENTICATOR_FLOW,AUTH_FLOW_ID,FLOW_ID,PRIORITY,REALM_ID,REQUIREMENT,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
docker-postgres-1  | 2023-12-03 09:25:13.710 UTC [219] DETAIL:  parameters: $1 = 'docker-http-basic-authenticator', $2 = NULL, $3 = 'f', $4 = NULL, $5 = '2f492243-f94b-4334-a13d-359c2fbe6031', $6 = '10', $7 = 'fkh-customers-sample', $8 = '0', $9 = '3248da47-0643-4020-ade2-e90dfc4fb71c'
docker-postgres-1  | 2023-12-03 09:25:13.712 UTC [219] LOG:  execute <unnamed>: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.712 UTC [219] DETAIL:  parameters: $1 = 'VERIFY_EMAIL', $2 = 'f', $3 = 't', $4 = 'Verify Email', $5 = '50', $6 = 'VERIFY_EMAIL', $7 = 'fkh-customers-sample', $8 = 'afd2e48a-e0de-4635-a51a-2ac6212b7d41'
docker-postgres-1  | 2023-12-03 09:25:13.715 UTC [219] LOG:  execute S_4: update REALM set ACCESS_CODE_LIFESPAN=$1,LOGIN_LIFESPAN=$2,USER_ACTION_LIFESPAN=$3,ACCESS_TOKEN_LIFESPAN=$4,ACCESS_TOKEN_LIFE_IMPLICIT=$5,ACCOUNT_THEME=$6,ADMIN_EVENTS_DETAILS_ENABLED=$7,ADMIN_EVENTS_ENABLED=$8,ADMIN_THEME=$9,ALLOW_USER_MANAGED_ACCESS=$10,BROWSER_FLOW=$11,CLIENT_AUTH_FLOW=$12,DEFAULT_LOCALE=$13,DEFAULT_ROLE=$14,DIRECT_GRANT_FLOW=$15,DOCKER_AUTH_FLOW=$16,DUPLICATE_EMAILS_ALLOWED=$17,EDIT_USERNAME_ALLOWED=$18,EMAIL_THEME=$19,ENABLED=$20,EVENTS_ENABLED=$21,EVENTS_EXPIRATION=$22,INTERNATIONALIZATION_ENABLED=$23,LOGIN_THEME=$24,LOGIN_WITH_EMAIL_ALLOWED=$25,MASTER_ADMIN_CLIENT=$26,NAME=$27,NOT_BEFORE=$28,OFFLINE_SESSION_IDLE_TIMEOUT=$29,OTP_POLICY_ALG=$30,OTP_POLICY_DIGITS=$31,OTP_POLICY_COUNTER=$32,OTP_POLICY_WINDOW=$33,OTP_POLICY_PERIOD=$34,OTP_POLICY_TYPE=$35,PASSWORD_POLICY=$36,REFRESH_TOKEN_MAX_REUSE=$37,REGISTRATION_ALLOWED=$38,REG_EMAIL_AS_USERNAME=$39,REGISTRATION_FLOW=$40,REMEMBER_ME=$41,RESET_CREDENTIALS_FLOW=$42,RESET_PASSWORD_ALLOWED=$43,REVOKE_REFRESH_TOKEN=$44,SSL_REQUIRED=$45,SSO_IDLE_TIMEOUT=$46,SSO_IDLE_TIMEOUT_REMEMBER_ME=$47,SSO_MAX_LIFESPAN=$48,SSO_MAX_LIFESPAN_REMEMBER_ME=$49,VERIFY_EMAIL=$50 where ID=$51
docker-postgres-1  | 2023-12-03 09:25:13.715 UTC [219] DETAIL:  parameters: $1 = '60', $2 = '1800', $3 = '300', $4 = '300', $5 = '900', $6 = NULL, $7 = 'f', $8 = 'f', $9 = NULL, $10 = 'f', $11 = '0778f648-540f-41af-8719-e7f0fac82fef', $12 = '7c14cafa-aa0e-49a6-bb76-71ca9db6690c', $13 = NULL, $14 = '12c4f394-a345-495a-be74-776f00efc836', $15 = '4599507d-63cd-4d28-a696-3513bc2ffd18', $16 = '2f492243-f94b-4334-a13d-359c2fbe6031', $17 = 'f', $18 = 'f', $19 = NULL, $20 = 't', $21 = 'f', $22 = '0', $23 = 'f', $24 = NULL, $25 = 't', $26 = '452726be-5e71-4e63-b92a-5df65c91569e', $27 = 'fkh-customers-sample', $28 = '0', $29 = '2592000', $30 = 'HmacSHA1', $31 = '6', $32 = '0', $33 = '1', $34 = '30', $35 = 'totp', $36 = NULL, $37 = '0', $38 = 'f', $39 = 'f', $40 = 'e27bc65f-e3aa-44d0-8c07-e1254088b71c', $41 = 'f', $42 = '3c8bd7f1-babd-414a-bb3d-d15658d44550', $43 = 'f', $44 = 'f', $45 = 'EXTERNAL', $46 = '1800', $47 = '0', $48 = '36000', $49 = '0', $50 = 'f', $51 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.717 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATOR_CONFIG_ENTRY (AUTHENTICATOR_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.717 UTC [219] DETAIL:  parameters: $1 = '1c049043-b23a-4880-ac03-7a58b033d97f', $2 = 'update.profile.on.first.login', $3 = 'missing'
docker-postgres-1  | 2023-12-03 09:25:13.719 UTC [219] LOG:  execute <unnamed>: insert into AUTHENTICATOR_CONFIG_ENTRY (AUTHENTICATOR_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.719 UTC [219] DETAIL:  parameters: $1 = '87b2aff3-0155-42c4-a5d3-63cb2e6e9778', $2 = 'require.password.update.after.registration', $3 = 'false'
docker-postgres-1  | 2023-12-03 09:25:13.768 UTC [219] LOG:  execute <unnamed>: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.768 UTC [219] DETAIL:  parameters: $1 = 'UPDATE_PROFILE', $2 = 'f', $3 = 't', $4 = 'Update Profile', $5 = '40', $6 = 'UPDATE_PROFILE', $7 = 'fkh-customers-sample', $8 = '5013a905-8954-4f53-b963-1aa3633b8c7b'
docker-postgres-1  | 2023-12-03 09:25:13.791 UTC [219] LOG:  execute <unnamed>: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.791 UTC [219] DETAIL:  parameters: $1 = 'CONFIGURE_TOTP', $2 = 'f', $3 = 't', $4 = 'Configure OTP', $5 = '10', $6 = 'CONFIGURE_TOTP', $7 = 'fkh-customers-sample', $8 = 'c7b2d935-5457-4879-a534-90e6359ae759'
docker-postgres-1  | 2023-12-03 09:25:13.822 UTC [219] LOG:  execute <unnamed>: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.822 UTC [219] DETAIL:  parameters: $1 = 'UPDATE_PASSWORD', $2 = 'f', $3 = 't', $4 = 'Update Password', $5 = '30', $6 = 'UPDATE_PASSWORD', $7 = 'fkh-customers-sample', $8 = '41b236d1-5b96-43e4-8c35-54cc0be68e7a'
docker-postgres-1  | 2023-12-03 09:25:13.835 UTC [219] LOG:  execute S_26: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.835 UTC [219] DETAIL:  parameters: $1 = 'TERMS_AND_CONDITIONS', $2 = 'f', $3 = 'f', $4 = 'Terms and Conditions', $5 = '20', $6 = 'TERMS_AND_CONDITIONS', $7 = 'fkh-customers-sample', $8 = '02d37cd6-ca85-4beb-9113-097834208a63'
docker-postgres-1  | 2023-12-03 09:25:13.843 UTC [219] LOG:  execute S_26: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.843 UTC [219] DETAIL:  parameters: $1 = 'delete_account', $2 = 'f', $3 = 'f', $4 = 'Delete Account', $5 = '60', $6 = 'delete_account', $7 = 'fkh-customers-sample', $8 = 'c0ae5c0f-6ee5-4347-9f7c-e1026fbd5b76'
docker-postgres-1  | 2023-12-03 09:25:13.849 UTC [219] LOG:  execute S_26: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.849 UTC [219] DETAIL:  parameters: $1 = 'update_user_locale', $2 = 'f', $3 = 't', $4 = 'Update User Locale', $5 = '1000', $6 = 'update_user_locale', $7 = 'fkh-customers-sample', $8 = '4aceabec-b5bd-41ff-8a4b-8b1d38c11cb4'
docker-postgres-1  | 2023-12-03 09:25:13.857 UTC [219] LOG:  execute S_26: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.857 UTC [219] DETAIL:  parameters: $1 = 'webauthn-register', $2 = 'f', $3 = 't', $4 = 'Webauthn Register', $5 = '70', $6 = 'webauthn-register', $7 = 'fkh-customers-sample', $8 = 'd630029c-59d0-47db-b274-b8ed73b69895'
docker-postgres-1  | 2023-12-03 09:25:13.863 UTC [219] LOG:  execute S_26: insert into REQUIRED_ACTION_PROVIDER (ALIAS,DEFAULT_ACTION,ENABLED,NAME,PRIORITY,PROVIDER_ID,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7,$8)
docker-postgres-1  | 2023-12-03 09:25:13.863 UTC [219] DETAIL:  parameters: $1 = 'webauthn-register-passwordless', $2 = 'f', $3 = 't', $4 = 'Webauthn Register Passwordless', $5 = '80', $6 = 'webauthn-register-passwordless', $7 = 'fkh-customers-sample', $8 = 'efd34ae8-9dcd-48c8-903f-151f30ff0c8d'
docker-postgres-1  | 2023-12-03 09:25:13.876 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER (ADD_TOKEN_ROLE,PROVIDER_ALIAS,AUTHENTICATE_BY_DEFAULT,PROVIDER_DISPLAY_NAME,ENABLED,FIRST_BROKER_LOGIN_FLOW_ID,LINK_ONLY,POST_BROKER_LOGIN_FLOW_ID,PROVIDER_ID,REALM_ID,STORE_TOKEN,TRUST_EMAIL,INTERNAL_ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
docker-postgres-1  | 2023-12-03 09:25:13.876 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'keycloak-oidc', $3 = 'f', $4 = NULL, $5 = 't', $6 = 'f97f67c2-6e15-42ea-a886-3907086513d7', $7 = 'f', $8 = NULL, $9 = 'keycloak-oidc', $10 = 'fkh-customers-sample', $11 = 'f', $12 = 'f', $13 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20'
docker-postgres-1  | 2023-12-03 09:25:13.881 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.881 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'clientId', $3 = 'ssss'
docker-postgres-1  | 2023-12-03 09:25:13.886 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.886 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'tokenUrl', $3 = 'http://localhost'
docker-postgres-1  | 2023-12-03 09:25:13.888 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.888 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'authorizationUrl', $3 = 'http://localhost'
docker-postgres-1  | 2023-12-03 09:25:13.890 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.890 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'clientAuthMethod', $3 = 'client_secret_basic'
docker-postgres-1  | 2023-12-03 09:25:13.893 UTC [219] LOG:  execute S_27: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.893 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'syncMode', $3 = 'IMPORT'
docker-postgres-1  | 2023-12-03 09:25:13.895 UTC [219] LOG:  execute S_27: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.895 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'clientSecret', $3 = 'assaasa'
docker-postgres-1  | 2023-12-03 09:25:13.897 UTC [219] LOG:  execute S_27: insert into IDENTITY_PROVIDER_CONFIG (IDENTITY_PROVIDER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.897 UTC [219] DETAIL:  parameters: $1 = 'd79d0d65-8ee1-47f0-8611-f9e6eea71f20', $2 = 'useJwksUrl', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:13.902 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER (ADD_TOKEN_ROLE,PROVIDER_ALIAS,AUTHENTICATE_BY_DEFAULT,PROVIDER_DISPLAY_NAME,ENABLED,FIRST_BROKER_LOGIN_FLOW_ID,LINK_ONLY,POST_BROKER_LOGIN_FLOW_ID,PROVIDER_ID,REALM_ID,STORE_TOKEN,TRUST_EMAIL,INTERNAL_ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
docker-postgres-1  | 2023-12-03 09:25:13.902 UTC [219] DETAIL:  parameters: $1 = 'f', $2 = 'keycloak-oidc-2', $3 = 'f', $4 = NULL, $5 = 't', $6 = 'f97f67c2-6e15-42ea-a886-3907086513d7', $7 = 'f', $8 = NULL, $9 = 'keycloak-oidc', $10 = 'fkh-customers-sample', $11 = 'f', $12 = 'f', $13 = '7cf3fd74-8d3a-4c8d-b651-fcc885df8a31'
docker-postgres-1  | 2023-12-03 09:25:13.915 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:13.915 UTC [219] DETAIL:  parameters: $1 = 'offline_access', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.922 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:13.922 UTC [219] DETAIL:  parameters: $1 = 'uma_authorization', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.928 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:13.928 UTC [219] DETAIL:  parameters: $1 = 'uma_authorization', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:13.935 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER_MAPPER (IDP_ALIAS,IDP_MAPPER_NAME,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:13.935 UTC [219] DETAIL:  parameters: $1 = 'keycloak-oidc2', $2 = 'keycloak-oidc', $3 = 'test-mapper', $4 = 'fkh-customers-sample', $5 = '2168f3db-1c2f-4b5a-ba5c-9dd22ead2aa5'
docker-postgres-1  | 2023-12-03 09:25:13.937 UTC [219] LOG:  execute <unnamed>: insert into IDENTITY_PROVIDER_MAPPER (IDP_ALIAS,IDP_MAPPER_NAME,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5)
docker-postgres-1  | 2023-12-03 09:25:13.937 UTC [219] DETAIL:  parameters: $1 = 'keycloak-oidc-2', $2 = 'hardcoded-user-session-attribute-idp-mapper', $3 = 'test', $4 = 'fkh-customers-sample', $5 = 'dd961620-6bbd-4b05-9594-e83522acfc7f'
docker-postgres-1  | 2023-12-03 09:25:13.939 UTC [219] LOG:  execute S_5: insert into KEYCLOAK_ROLE (CLIENT,CLIENT_REALM_CONSTRAINT,CLIENT_ROLE,DESCRIPTION,NAME,REALM_ID,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:13.939 UTC [219] DETAIL:  parameters: $1 = NULL, $2 = 'fkh-customers-sample', $3 = 'f', $4 = NULL, $5 = 'uma_authorization', $6 = 'fkh-customers-sample', $7 = '9a935466-e764-4a95-832b-72eb63e03ae9'
docker-postgres-1  | 2023-12-03 09:25:13.943 UTC [219] LOG:  execute <unnamed>: insert into IDP_MAPPER_CONFIG (IDP_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:13.943 UTC [219] DETAIL:  parameters: $1 = 'dd961620-6bbd-4b05-9594-e83522acfc7f', $2 = 'syncMode', $3 = 'INHERIT'
docker-postgres-1  | 2023-12-03 09:25:13.950 UTC [219] LOG:  execute S_8: insert into COMPOSITE_ROLE (COMPOSITE,CHILD_ROLE) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:13.950 UTC [219] DETAIL:  parameters: $1 = '12c4f394-a345-495a-be74-776f00efc836', $2 = '9a935466-e764-4a95-832b-72eb63e03ae9'
docker-postgres-1  | 2023-12-03 09:25:15.141 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:15.141 UTC [219] DETAIL:  parameters: $1 = 'security-admin-console', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:15.152 UTC [219] LOG:  execute S_10: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:15.152 UTC [219] DETAIL:  parameters: $1 = 'account', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:15.161 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.161 UTC [219] DETAIL:  parameters: $1 = 'delete-account', $2 = '18f4e62c-d75b-4b5b-9c64-99de054e1ec2'
docker-postgres-1  | 2023-12-03 09:25:15.169 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:15.169 UTC [219] DETAIL:  parameters: $1 = 'uma_authorization', $2 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:25:15.192 UTC [219] LOG:  execute S_14: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT_ROLE=false and r1_0.NAME=$1 and r1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:25:15.192 UTC [219] DETAIL:  parameters: $1 = 'admin', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:25:15.199 UTC [219] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT=$1 order by r1_0.NAME
docker-postgres-1  | 2023-12-03 09:25:15.199 UTC [219] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-03 09:25:15.210 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.210 UTC [219] DETAIL:  parameters: $1 = 'create-client', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.215 UTC [219] LOG:  execute <unnamed>: select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT,u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME from USER_ENTITY u1_0 where u1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.215 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.224 UTC [219] LOG:  execute <unnamed>: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.224 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.232 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.232 UTC [219] DETAIL:  parameters: $1 = 'rsa-generated', $2 = 'fkh-customers-sample', $3 = 'rsa-generated', $4 = 'org.keycloak.keys.KeyProvider', $5 = 'fkh-customers-sample', $6 = NULL, $7 = '666788fe-7de5-4e6b-88a2-c081b3115c7e'
docker-postgres-1  | 2023-12-03 09:25:15.235 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.235 UTC [219] DETAIL:  parameters: $1 = 'rsa-enc-generated', $2 = 'fkh-customers-sample', $3 = 'rsa-enc-generated', $4 = 'org.keycloak.keys.KeyProvider', $5 = 'fkh-customers-sample', $6 = NULL, $7 = 'a9082ecf-936e-4994-9617-31aa8688331c'
docker-postgres-1  | 2023-12-03 09:25:15.239 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.239 UTC [219] DETAIL:  parameters: $1 = 'hmac-generated', $2 = 'fkh-customers-sample', $3 = 'hmac-generated', $4 = 'org.keycloak.keys.KeyProvider', $5 = 'fkh-customers-sample', $6 = NULL, $7 = '2e16262a-a140-45f0-9675-1f285d35f590'
docker-postgres-1  | 2023-12-03 09:25:15.241 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.241 UTC [219] DETAIL:  parameters: $1 = 'aes-generated', $2 = 'fkh-customers-sample', $3 = 'aes-generated', $4 = 'org.keycloak.keys.KeyProvider', $5 = 'fkh-customers-sample', $6 = NULL, $7 = '2bc03384-1ded-491c-9688-eda0f8a748ea'
docker-postgres-1  | 2023-12-03 09:25:15.242 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.242 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c', $2 = 'privateKey', $3 = 'MIIEpAIBAAKCAQEAsjUNgZVCQ5RiJiaAhRjQHSXrV6qRj9V0md0KTAT7NIbWsFJkliQbZYaXODsvTAvedTDkP398EvwA1qJwYE7HRfk605ysiL5Ot8zeIi5zdL0yEpPjXtKE4SkgpBRWJu4eQLmcD9cayECTmVTe6w1QmNDau6qf+a6qhi0JkBljT0sGpczdFEwCtokyBetiFp4RWXfbcBYrT0FxvgQvCgbwPmm8ko1sOniu9IHejYkaLIpkmz8Tlyvf3YPz1OLhVCjohgGkMhWH7PTcRepQ7pYIYFCHghh2bvC1tDbsT9Av3vDdQR2zB+1mL4loTG4HUIRr28oJfsmDeo/Zj+H2SCSd9wIDAQABAoIBABS+hJF320xRlVvv3G23NeFGvOP/aM1aTCXtq0QDym19YA1gsfEg8ogkHYNABHabj8GK4kRFUJ9HHXPeryp5e8yN7AaeX3PVhK/0QEwF+zj0yG44L937BIPPTUuRoHZh/pHgk/rrZQ84JoD79lex55a6V9PuUzaghJzKLlRLWETuT/ENCBczWwALBOWFkTBo6xBdWuQP8UJYUjL4PmStGNk6UkTBYcEnxKSu56ZaOblTn4wcB8qlnV6bSbqSwRsYiC1P2snmPyIi2dmVLkqy6+Vi0XZwZASVqv5a9sFiYcL8Kwk5JFU2lmw2jjv5KpNa8ZhW29rluxjo4oC2M17iFfUCgYEA8ISFec7RxzlBml2yaw5ygwy7DsXpLTLXxg5y475ZyvsFelQxseWwrgDOFE5KoUZ3AJCfBxExxbQjHOUf6zgoc2WLp744wnKKfn3mq6lfWrOuGIkur3LlMK77MVz5dL7YBX/Aojt5WUIKwQ+/VaqLDW/W/g3tYmAeC9N98u+4gjMCgYEAva24kglM8joU0TeOcx7Z21v5nN8OS0bQmAGQ1aL5llyJbcI7XKUIJh4sK3mhsow4mTLyYOVuxfznjb9/Ahr8IAggHzE2K+XU54SQV7rhGXt7tVOwhPwLWtPT6xRyb4ggM8WhZwFuX/REs8ffyToX9pTfov3z3Bx20scCnITGWS0CgYEAkjbt8cPiUaukDxTA30Y0JSj7GpsECv8qn3OvMnZInhYGGXzPjSdmRhGlNkD2K57rv0Mr+h7g1CCTbAB6bAOCy8xCnyIL3WHGgelF7ruThU9QGghjgjNl0ze86yBrYiaWqpkkYTuopLN6WC2bkpeP2wZPe7i5xCFMgsH6glJrJ3MCgYBg1PwBya+3hUE1YaheSuSrILQ4ioLwmRFKWJpJBi9mvI0INH07maCkXQjtlOWgkgce5qxoHRjFCIxph9ZeC8qky6Eia2wdUvKy0rEhqGzcJncMJdJawZVGZBeuzjxxhcvywjTYshlX8QrVwPcU8oxjPLNCsWS5/OoIRsKlhv7/bQKBgQDbpa0ACYm5WHO4hc0s++ZCd7lqhPK6HZl9MGFwxJMzo1vBKIehgtZJcxQlLCIQasct6ErBc+PNI+Y6vipmXzhDX2DLxKUPoda5PIHNsywbBAeFC8onTAwT/vG26ujGMLbuUkOlClxmUhU2zY6xd8U4hd4ZvstwGN4JjUspB8vkJQ==', $4 = '7f11c978-e5fc-4a72-b360-8671747b8a0e'
docker-postgres-1  | 2023-12-03 09:25:15.245 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.245 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c', $2 = 'priority', $3 = '100', $4 = '98782029-961d-40f9-913c-57f90a52768c'
docker-postgres-1  | 2023-12-03 09:25:15.246 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.246 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c', $2 = 'certificate', $3 = 'MIICtzCCAZ8CBgGMLv8I4zANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRma2gtY3VzdG9tZXJzLXNhbXBsZTAeFw0yMzEyMDMwOTIzMzVaFw0zMzEyMDMwOTI1MTVaMB8xHTAbBgNVBAMMFGZraC1jdXN0b21lcnMtc2FtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjUNgZVCQ5RiJiaAhRjQHSXrV6qRj9V0md0KTAT7NIbWsFJkliQbZYaXODsvTAvedTDkP398EvwA1qJwYE7HRfk605ysiL5Ot8zeIi5zdL0yEpPjXtKE4SkgpBRWJu4eQLmcD9cayECTmVTe6w1QmNDau6qf+a6qhi0JkBljT0sGpczdFEwCtokyBetiFp4RWXfbcBYrT0FxvgQvCgbwPmm8ko1sOniu9IHejYkaLIpkmz8Tlyvf3YPz1OLhVCjohgGkMhWH7PTcRepQ7pYIYFCHghh2bvC1tDbsT9Av3vDdQR2zB+1mL4loTG4HUIRr28oJfsmDeo/Zj+H2SCSd9wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBrmBx3OWoWXX9IzRe6MPfxQ18ZZtTc47Pp6Jc9hq4DbGSEIn2zZ7nJKpupHN1Hxesokj1OIz6RIpoJSOrijTNnlnlSOtWIwbChsX8RaO27M719yRZaYHhX9FeyvxfprGM6ZzTvA86YWgX8r7uuo+vNrh/o+xfwIC4l61S2s2s/j9QegV3BzPXNRj6LCUTqQZBU3IZ2yGAqrwZHeXIPInqJ0r/u1XAy8ZfC1ijiNyCwKy/YoF8WqtUGjc18XoGF8mS+KWmbjjm05QzdLGz7DXJX9L6Vhs+Q7vHLqmwzcmisZ/wAEWAU2HOAJGp28UXfr0sbB1GxoQaQ6hPv74iHu8K/', $4 = 'b6e845fc-07bd-4546-9e9c-a23b386816a4'
docker-postgres-1  | 2023-12-03 09:25:15.250 UTC [219] LOG:  execute <unnamed>: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.250 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c', $2 = 'keyUse', $3 = 'ENC', $4 = '55ff84a2-d94b-4338-978b-9f2953781a2c'
docker-postgres-1  | 2023-12-03 09:25:15.251 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.251 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c', $2 = 'algorithm', $3 = 'RSA-OAEP', $4 = 'b144642f-4f3c-4ed3-b511-7bd915e5d60c'
docker-postgres-1  | 2023-12-03 09:25:15.251 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.251 UTC [219] DETAIL:  parameters: $1 = '666788fe-7de5-4e6b-88a2-c081b3115c7e', $2 = 'priority', $3 = '100', $4 = 'eebdf63a-cdd5-4d4f-9e82-4790448b2514'
docker-postgres-1  | 2023-12-03 09:25:15.252 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.252 UTC [219] DETAIL:  parameters: $1 = '666788fe-7de5-4e6b-88a2-c081b3115c7e', $2 = 'privateKey', $3 = 'MIIEowIBAAKCAQEAnpxzkPHGVI+xak+AJ0yeDxvRCIN9F4vzDsK5xVELbg8hBKBrPew1tN56oo71QHxtaW96IDf5lit/zk/CDkBR9wZtp5DchYTQo2oaDj7V4hVyMkcBALWTyuglUHsCE+XNLXjSR3H+FwH3NUhcnSVg/LvgOItO/RlVQWX823gkc03SAVhHdoQi4pIWpX+iA+MhmMjIsUwOviEZ0MxP3W0CgVEfBVrAB3KXuc//NlBdisheEwLvvk4MdGsKogiHqga0X1EnqI/5yhgDsbRLzksxS4mlSd+LNZRdZh58nAGAvLkDP+qXp/lYlG6O6VhPTOSCp92De+jbTLr/NWmm3DY5EwIDAQABAoIBAAuiJax4Z0Jq2v7qqizNEadsXrZqpSwAdPPctBvKWCBwQKI3vUCTSNR6yvDjCQ778VnIi429vUiBPpmxv5B5sZQA5zML93iy50tNFsXRCwakPwt7/2aqFWx4/spP3gpP58Qm4U7MiBqaPM5Y1TN7ezPI+JGnz26AmKsNdsXcIoRIZSSM4TXh8BOAcAKL8nZP1k6Hwt6u/aXwW2JOOR5qvMCbwRWP9LDMDG5o35g67yCltjVmJLNtV4QDofJU4kGfaHvX1w0uFKf1IseQTyaBQsGMnbyibkKRrS8RHirkOio7SvWVZHGmqkjHEDuBX7X9z3Gl3kttJ9RMDcEEacCoPAUCgYEA1mSjGWaaDQszqRLWoiLq/N6X7H1BBDzd47Y+u4xkX1AePlsEWBuBAIOPkq9RFoCj4jewWyQsVIw+/olJg5JOXDkOXbFTX05QsUO6ulr9Di0ygc0oyqKmmyODfU9Cvrd5g+RUQfjo/jysmdExtl9ww9xacjw/tkfilzot97tMJ8UCgYEAvWR7/n0+gnIJbave+b2JgOfGkoZDLK6nyelLAvFUKlUcmMlQQkysWkURUUNJn6onhvR8Ww23S4/qnRVR8J4o8VuiYgYWqowoUWOqMbZRGMmtNtL0m4rPc2G36ZjLKfRpexqPEEcycO+YFCYQJY1kZtViLM++Idf/9wS2hF4wEvcCgYBH/SbfApq7woUoQpEbhEoPetbcq/pG6AFB0xIhe7TAZHCjU4CT7ThV6dct0/yQZ8Wf0j8/e1f/U9BbO9IZgekaAnaWc1Khb/SccTekF6VdO0P4XeFSmWcENNqUGyc4TvdYmDTKqj/iDpGOXLYqnMWKntUoAp8KH/0v9nM0+glKWQKBgBp9xrZHMIowh08W3l6Se3xTbzwpmZXTbFba0go8VWiCdTiN2DMd5HHP/WcfgVnbBCJlakuWNJBWNhv40nhUtydjiOgrL9p1NmKEDVdcyCUueJMVmO900CW0gnQjUi+xJ1v30BEX1F9ltCEFXfbSuzuDF3NrL44uV3hm6VzEi/brAoGBAIZZZ+HkpgZsfrMIegh0e1WF8SStKu5ukpgDzJtaqkrr/zbuyA03chDy9YvmSNjZfEHiIOV4sZ/6mwgf1Qo6XylEhjEYeYGyLsJZjyHLNH861BzgbNxrgQNJVi/Z0NIBiEF2ucQWOOTAHUeI4Yl54vU9xg+j7vvNkx5O5iXJmw4H', $4 = 'a127cb2c-d86c-4aef-9b06-a3d845f95da8'
docker-postgres-1  | 2023-12-03 09:25:15.255 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.255 UTC [219] DETAIL:  parameters: $1 = '666788fe-7de5-4e6b-88a2-c081b3115c7e', $2 = 'keyUse', $3 = 'SIG', $4 = 'dfc537bf-5c24-4b19-85b1-edb870ca1a13'
docker-postgres-1  | 2023-12-03 09:25:15.256 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.256 UTC [219] DETAIL:  parameters: $1 = '666788fe-7de5-4e6b-88a2-c081b3115c7e', $2 = 'certificate', $3 = 'MIICtzCCAZ8CBgGMLv8F4jANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRma2gtY3VzdG9tZXJzLXNhbXBsZTAeFw0yMzEyMDMwOTIzMzRaFw0zMzEyMDMwOTI1MTRaMB8xHTAbBgNVBAMMFGZraC1jdXN0b21lcnMtc2FtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnpxzkPHGVI+xak+AJ0yeDxvRCIN9F4vzDsK5xVELbg8hBKBrPew1tN56oo71QHxtaW96IDf5lit/zk/CDkBR9wZtp5DchYTQo2oaDj7V4hVyMkcBALWTyuglUHsCE+XNLXjSR3H+FwH3NUhcnSVg/LvgOItO/RlVQWX823gkc03SAVhHdoQi4pIWpX+iA+MhmMjIsUwOviEZ0MxP3W0CgVEfBVrAB3KXuc//NlBdisheEwLvvk4MdGsKogiHqga0X1EnqI/5yhgDsbRLzksxS4mlSd+LNZRdZh58nAGAvLkDP+qXp/lYlG6O6VhPTOSCp92De+jbTLr/NWmm3DY5EwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBw7c9A10f4sLHFHQBE2NUQEwLqeq8war9QT0cB/NV3/ENpTE8WtVh9RKRhZhL/vCAScbU4QjOes39HmbULInT0LHi4n5of7r6wpEHPYO6fdYws0a7X9ID+6FDkPXTcrqTxH7i3YpuX7pOY6nQPu+D529rQevM/TYX1NRFMu7ns3C5yTMOZYJ56+OnBEl0a05tisf6QNH4jYm5Sx+z7kyRphFckMLwr5gwPbPFBonqEvoHutdLpAXEFN9h1UzQ3biROE+LxsYy/QyAGD1NtZ/Bq9IkLU+1oXsiHdAo7EWGY4OrvpnZ6K0g+ydOs3QdljYb2M+gpu93Ckl8vke60j9SG', $4 = '70c881c1-4fc2-4ad3-b6a1-3a93b96fae14'
docker-postgres-1  | 2023-12-03 09:25:15.258 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.258 UTC [219] DETAIL:  parameters: $1 = '2bc03384-1ded-491c-9688-eda0f8a748ea', $2 = 'secret', $3 = 'zkK7mZb--Rjk1HEpHegw7A', $4 = '417702fb-710b-4c65-8381-2902b68539df'
docker-postgres-1  | 2023-12-03 09:25:15.259 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.259 UTC [219] DETAIL:  parameters: $1 = '2bc03384-1ded-491c-9688-eda0f8a748ea', $2 = 'priority', $3 = '100', $4 = '25e3452a-129c-46f1-bb0f-91622bda6e98'
docker-postgres-1  | 2023-12-03 09:25:15.262 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.262 UTC [219] DETAIL:  parameters: $1 = '2bc03384-1ded-491c-9688-eda0f8a748ea', $2 = 'kid', $3 = 'fe4c67e0-cab7-4ee0-b265-542faa2879e9', $4 = 'b24af400-b15a-42aa-8c52-dbeb9df00268'
docker-postgres-1  | 2023-12-03 09:25:15.264 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.264 UTC [219] DETAIL:  parameters: $1 = '2e16262a-a140-45f0-9675-1f285d35f590', $2 = 'kid', $3 = 'bfaaf3fa-b54c-43b4-8364-51a44780b415', $4 = 'e746476e-1dec-4bba-a3ff-3afc6dd5ef4c'
docker-postgres-1  | 2023-12-03 09:25:15.266 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.266 UTC [219] DETAIL:  parameters: $1 = '2e16262a-a140-45f0-9675-1f285d35f590', $2 = 'secret', $3 = 'zUDF0rcTiS8HBL4HD05q5gd7YdFh1UxHCS2gmNPJ-Q1ygv1BzqQSn3OE3nVP6laio2XU7xV4ANUhztlpP8VGnA', $4 = 'd6406690-ab8e-44b3-a4a8-b9e7e3fe132c'
docker-postgres-1  | 2023-12-03 09:25:15.269 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.269 UTC [219] DETAIL:  parameters: $1 = '2e16262a-a140-45f0-9675-1f285d35f590', $2 = 'priority', $3 = '100', $4 = '2c386451-f55a-4c6a-b911-025017b6f75d'
docker-postgres-1  | 2023-12-03 09:25:15.272 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.272 UTC [219] DETAIL:  parameters: $1 = '2e16262a-a140-45f0-9675-1f285d35f590', $2 = 'algorithm', $3 = 'HS256', $4 = 'bf060896-592f-43e8-85b1-24307ffe8f96'
docker-postgres-1  | 2023-12-03 09:25:15.274 UTC [219] LOG:  execute S_17: insert into PROTOCOL_MAPPER (CLIENT_ID,CLIENT_SCOPE_ID,NAME,PROTOCOL,PROTOCOL_MAPPER_NAME,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:25:15.274 UTC [219] DETAIL:  parameters: $1 = '63310b6e-7601-42ce-86a9-b008c64c019d', $2 = NULL, $3 = 'locale', $4 = 'openid-connect', $5 = 'oidc-usermodel-attribute-mapper', $6 = '48d3722c-8893-423c-9ad7-97724c8a1886'
docker-postgres-1  | 2023-12-03 09:25:15.277 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.277 UTC [219] DETAIL:  parameters: $1 = 'Trusted Hosts', $2 = 'fkh-customers-sample', $3 = 'trusted-hosts', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'anonymous', $7 = '4f96b61a-0792-46ef-a50b-1c337908b78c'
docker-postgres-1  | 2023-12-03 09:25:15.279 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.279 UTC [219] DETAIL:  parameters: $1 = 'Consent Required', $2 = 'fkh-customers-sample', $3 = 'consent-required', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'anonymous', $7 = '5f622371-82bb-41ee-83d8-70f6a2fb5b77'
docker-postgres-1  | 2023-12-03 09:25:15.281 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.281 UTC [219] DETAIL:  parameters: $1 = 'Full Scope Disabled', $2 = 'fkh-customers-sample', $3 = 'scope', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'anonymous', $7 = 'ca0ffeb5-dd26-4212-b2db-6c9c1f0079fd'
docker-postgres-1  | 2023-12-03 09:25:15.283 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.283 UTC [219] DETAIL:  parameters: $1 = 'Max Clients Limit', $2 = 'fkh-customers-sample', $3 = 'max-clients', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'anonymous', $7 = '1f3c3d71-2100-400e-8ec7-20b5f7a3e2ab'
docker-postgres-1  | 2023-12-03 09:25:15.287 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.287 UTC [219] DETAIL:  parameters: $1 = 'Allowed Protocol Mapper Types', $2 = 'fkh-customers-sample', $3 = 'allowed-protocol-mappers', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'anonymous', $7 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9'
docker-postgres-1  | 2023-12-03 09:25:15.289 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.289 UTC [219] DETAIL:  parameters: $1 = 'Allowed Client Scopes', $2 = 'fkh-customers-sample', $3 = 'allowed-client-templates', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'anonymous', $7 = 'ede16273-de0f-4bc8-a03d-777715b18cf3'
docker-postgres-1  | 2023-12-03 09:25:15.291 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.291 UTC [219] DETAIL:  parameters: $1 = 'Allowed Protocol Mapper Types', $2 = 'fkh-customers-sample', $3 = 'allowed-protocol-mappers', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'authenticated', $7 = 'f724059e-4d6c-47df-9e5e-4f724a306fec'
docker-postgres-1  | 2023-12-03 09:25:15.293 UTC [219] LOG:  execute S_29: insert into COMPONENT (NAME,PARENT_ID,PROVIDER_ID,PROVIDER_TYPE,REALM_ID,SUB_TYPE,ID) values ($1,$2,$3,$4,$5,$6,$7)
docker-postgres-1  | 2023-12-03 09:25:15.293 UTC [219] DETAIL:  parameters: $1 = 'Allowed Client Scopes', $2 = 'fkh-customers-sample', $3 = 'allowed-client-templates', $4 = 'org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy', $5 = 'fkh-customers-sample', $6 = 'authenticated', $7 = '3fb064a4-0ea1-45c4-b823-8940f3db9eff'
docker-postgres-1  | 2023-12-03 09:25:15.296 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.296 UTC [219] DETAIL:  parameters: $1 = '4f96b61a-0792-46ef-a50b-1c337908b78c', $2 = 'host-sending-registration-request-must-match', $3 = 'true', $4 = 'f5a831e6-55a9-49e6-b37b-f75e03408a1c'
docker-postgres-1  | 2023-12-03 09:25:15.298 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.298 UTC [219] DETAIL:  parameters: $1 = '4f96b61a-0792-46ef-a50b-1c337908b78c', $2 = 'client-uris-must-match', $3 = 'true', $4 = 'cc3ca445-c24d-4302-a277-fd45a9dc0314'
docker-postgres-1  | 2023-12-03 09:25:15.300 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.300 UTC [219] DETAIL:  parameters: $1 = '3fb064a4-0ea1-45c4-b823-8940f3db9eff', $2 = 'allow-default-scopes', $3 = 'true', $4 = '61544d42-d962-476b-867f-ea25d2ce0e28'
docker-postgres-1  | 2023-12-03 09:25:15.302 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.302 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'saml-user-property-mapper', $4 = '8b5d27c4-1c20-4da9-807b-a7da00a55289'
docker-postgres-1  | 2023-12-03 09:25:15.304 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.304 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'saml-user-attribute-mapper', $4 = '3b955def-29ba-44db-90e3-6a6c1b32a34f'
docker-postgres-1  | 2023-12-03 09:25:15.306 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.306 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'saml-role-list-mapper', $4 = '6186553e-fc31-49c4-8f00-8dd5160ae779'
docker-postgres-1  | 2023-12-03 09:25:15.308 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.308 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-usermodel-property-mapper', $4 = '79e9eabb-8d89-4c9f-bc62-f9ff3d2dfd00'
docker-postgres-1  | 2023-12-03 09:25:15.311 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.311 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-usermodel-attribute-mapper', $4 = '37141cd0-cb26-48e3-a143-d2653fe1b335'
docker-postgres-1  | 2023-12-03 09:25:15.313 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.313 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-sha256-pairwise-sub-mapper', $4 = '8d0caeed-b331-448c-adcc-a7243cf0838e'
docker-postgres-1  | 2023-12-03 09:25:15.316 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.316 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-full-name-mapper', $4 = 'd3adc448-191e-43a4-9573-af1578032ae1'
docker-postgres-1  | 2023-12-03 09:25:15.318 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.318 UTC [219] DETAIL:  parameters: $1 = '6cceccd7-0fbd-46ea-a907-57cf369f66d9', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-address-mapper', $4 = 'c8081ff0-374e-4855-b035-cabb0fa805fd'
docker-postgres-1  | 2023-12-03 09:25:15.321 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.321 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-full-name-mapper', $4 = 'dabc4fa4-8cd0-43f5-9f21-6b5fbf1c5196'
docker-postgres-1  | 2023-12-03 09:25:15.323 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.323 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-usermodel-property-mapper', $4 = '55fac81e-1c47-4a59-9377-a527557c0890'
docker-postgres-1  | 2023-12-03 09:25:15.325 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.325 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'saml-user-attribute-mapper', $4 = 'a7c72810-c8d1-4b10-b73c-1d93cd4bc296'
docker-postgres-1  | 2023-12-03 09:25:15.328 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.328 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-address-mapper', $4 = '41ccea08-76d8-487a-8c4b-05272147b48c'
docker-postgres-1  | 2023-12-03 09:25:15.330 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.330 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-usermodel-attribute-mapper', $4 = 'cbc65495-9685-4133-8c3e-2b893e5143de'
docker-postgres-1  | 2023-12-03 09:25:15.332 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.332 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'oidc-sha256-pairwise-sub-mapper', $4 = '1489abb5-d453-4ff9-be86-ddf8e029e2be'
docker-postgres-1  | 2023-12-03 09:25:15.334 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.334 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'saml-user-property-mapper', $4 = '72e1c6c8-3966-499b-97b2-c804bbeda46e'
docker-postgres-1  | 2023-12-03 09:25:15.337 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.337 UTC [219] DETAIL:  parameters: $1 = 'f724059e-4d6c-47df-9e5e-4f724a306fec', $2 = 'allowed-protocol-mapper-types', $3 = 'saml-role-list-mapper', $4 = 'b8ad6a86-a182-460e-afec-e3d243be2924'
docker-postgres-1  | 2023-12-03 09:25:15.339 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.339 UTC [219] DETAIL:  parameters: $1 = 'ede16273-de0f-4bc8-a03d-777715b18cf3', $2 = 'allow-default-scopes', $3 = 'true', $4 = '05b832c1-18f8-43c8-8a69-7169226f4a7d'
docker-postgres-1  | 2023-12-03 09:25:15.341 UTC [219] LOG:  execute S_28: insert into COMPONENT_CONFIG (COMPONENT_ID,NAME,VALUE,ID) values ($1,$2,$3,$4)
docker-postgres-1  | 2023-12-03 09:25:15.341 UTC [219] DETAIL:  parameters: $1 = '1f3c3d71-2100-400e-8ec7-20b5f7a3e2ab', $2 = 'max-clients', $3 = '200', $4 = 'd5fb1af9-1f5e-417b-9a8f-1bd217803409'
docker-postgres-1  | 2023-12-03 09:25:15.343 UTC [219] LOG:  execute <unnamed>: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.343 UTC [219] DETAIL:  parameters: $1 = '862a17e6-7729-402e-ac89-c4a883171ac2', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.346 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:15.346 UTC [219] DETAIL:  parameters: $1 = '48d3722c-8893-423c-9ad7-97724c8a1886', $2 = 'userinfo.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:15.347 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:15.347 UTC [219] DETAIL:  parameters: $1 = '48d3722c-8893-423c-9ad7-97724c8a1886', $2 = 'user.attribute', $3 = 'locale'
docker-postgres-1  | 2023-12-03 09:25:15.349 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:15.349 UTC [219] DETAIL:  parameters: $1 = '48d3722c-8893-423c-9ad7-97724c8a1886', $2 = 'id.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:15.352 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:15.352 UTC [219] DETAIL:  parameters: $1 = '48d3722c-8893-423c-9ad7-97724c8a1886', $2 = 'access.token.claim', $3 = 'true'
docker-postgres-1  | 2023-12-03 09:25:15.355 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:15.355 UTC [219] DETAIL:  parameters: $1 = '48d3722c-8893-423c-9ad7-97724c8a1886', $2 = 'claim.name', $3 = 'locale'
docker-postgres-1  | 2023-12-03 09:25:15.357 UTC [219] LOG:  execute S_18: insert into PROTOCOL_MAPPER_CONFIG (PROTOCOL_MAPPER_ID,NAME,VALUE) values ($1,$2,$3)
docker-postgres-1  | 2023-12-03 09:25:15.357 UTC [219] DETAIL:  parameters: $1 = '48d3722c-8893-423c-9ad7-97724c8a1886', $2 = 'jsonType.label', $3 = 'String'
docker-postgres-1  | 2023-12-03 09:25:15.363 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.363 UTC [219] DETAIL:  parameters: $1 = 'view-realm', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.369 UTC [219] LOG:  execute <unnamed>: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.369 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.376 UTC [219] LOG:  execute <unnamed>: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.376 UTC [219] DETAIL:  parameters: $1 = '0e912919-0395-44bb-8227-82b22e69544c', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.382 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.382 UTC [219] DETAIL:  parameters: $1 = 'view-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.388 UTC [219] LOG:  execute <unnamed>: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.388 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.394 UTC [219] LOG:  execute <unnamed>: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.394 UTC [219] DETAIL:  parameters: $1 = '66ad1f2a-bed9-4f95-be2e-9f9d00e5f523', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.399 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.399 UTC [219] DETAIL:  parameters: $1 = 'view-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.404 UTC [219] LOG:  execute <unnamed>: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.404 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.409 UTC [219] LOG:  execute <unnamed>: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.409 UTC [219] DETAIL:  parameters: $1 = '54fc9ee1-2e73-4826-a9e3-77336f56137c', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.415 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.415 UTC [219] DETAIL:  parameters: $1 = 'view-events', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.420 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.420 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.427 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.427 UTC [219] DETAIL:  parameters: $1 = '6b81e36d-d47f-470e-a652-244d16b96ef8', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.433 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.433 UTC [219] DETAIL:  parameters: $1 = 'view-identity-providers', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.439 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.439 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.445 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.445 UTC [219] DETAIL:  parameters: $1 = '5bd79518-7d2c-4bc5-8675-779a3839c112', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.450 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.450 UTC [219] DETAIL:  parameters: $1 = 'view-authorization', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.459 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.459 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.464 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.464 UTC [219] DETAIL:  parameters: $1 = '111b596f-af5e-4cae-9d5a-664995851c47', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.469 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.469 UTC [219] DETAIL:  parameters: $1 = 'manage-realm', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.474 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.474 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.481 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.481 UTC [219] DETAIL:  parameters: $1 = 'ebe7ada5-ce06-46ca-88ae-d2cda627e765', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.485 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.485 UTC [219] DETAIL:  parameters: $1 = 'manage-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.490 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.490 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.496 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.496 UTC [219] DETAIL:  parameters: $1 = '532fd183-929d-4cf5-be4f-822c4bac154f', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.500 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.500 UTC [219] DETAIL:  parameters: $1 = 'manage-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.506 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.506 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.512 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.512 UTC [219] DETAIL:  parameters: $1 = 'e0800932-994a-4607-8dd3-caf9d85bdd3a', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.528 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.528 UTC [219] DETAIL:  parameters: $1 = 'manage-events', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.532 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.532 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.537 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.537 UTC [219] DETAIL:  parameters: $1 = '6ba1c8ff-7c24-461c-bd2f-6a184ca99239', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.542 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.542 UTC [219] DETAIL:  parameters: $1 = 'manage-identity-providers', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.547 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.547 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.552 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.552 UTC [219] DETAIL:  parameters: $1 = '34a24d1b-ad7e-4d64-8c15-6f95cbc74112', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.557 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.557 UTC [219] DETAIL:  parameters: $1 = 'manage-authorization', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.566 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.566 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.574 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.574 UTC [219] DETAIL:  parameters: $1 = 'a6011000-139e-4caa-a6ce-b6cf95e9951f', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.580 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.580 UTC [219] DETAIL:  parameters: $1 = 'query-users', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.585 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.585 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.590 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.590 UTC [219] DETAIL:  parameters: $1 = '3d63342c-313f-43cd-96f3-9d4ee4223e58', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.596 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.596 UTC [219] DETAIL:  parameters: $1 = 'query-clients', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.601 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.601 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.607 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.607 UTC [219] DETAIL:  parameters: $1 = '1f7abdb8-a271-4c38-9a69-ce157a850d62', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.613 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.613 UTC [219] DETAIL:  parameters: $1 = 'query-realms', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.617 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.617 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.623 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.623 UTC [219] DETAIL:  parameters: $1 = '66b66ac8-171e-4802-89ee-2cd19ee3a2d9', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.628 UTC [219] LOG:  execute S_7: select r1_0.ID from KEYCLOAK_ROLE r1_0 where r1_0.NAME=$1 and r1_0.CLIENT=$2
docker-postgres-1  | 2023-12-03 09:25:15.628 UTC [219] DETAIL:  parameters: $1 = 'query-groups', $2 = '452726be-5e71-4e63-b92a-5df65c91569e'
docker-postgres-1  | 2023-12-03 09:25:15.633 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:25:15.633 UTC [219] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.640 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:25:15.640 UTC [219] DETAIL:  parameters: $1 = 'bcb1948c-2ed3-463c-b80f-ad6f41129917', $2 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-03 09:25:15.665 UTC [219] LOG:  execute S_1: COMMIT





# Request
curl --location 'http://localhost:8080/admin/realms/fkh-customers-sample/clients-initial-access' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ access_token }}' \  # note that access token is for admin-cli user in the master realm, but this token request is on the fkh-customers-sample realm
--data '{
	"count": 5,
	"expiration": 5
}'


# Response
{
    "id": "b4021e67-45f2-4a62-a914-116064016bd8",
    "token": "{{ tenant_access_token }}",
    "timestamp": 1701597196,
    "expiration": 5,
    "count": 5,
    "remainingCount": 5
}


# DB Queries

docker-postgres-1  | 2023-12-03 09:57:38.349 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 09:57:38.352 UTC [219] LOG:  execute S_57: select r1_0.ID,r1_0.ACCESS_CODE_LIFESPAN,r1_0.LOGIN_LIFESPAN,r1_0.USER_ACTION_LIFESPAN,r1_0.ACCESS_TOKEN_LIFESPAN,r1_0.ACCESS_TOKEN_LIFE_IMPLICIT,r1_0.ACCOUNT_THEME,r1_0.ADMIN_EVENTS_DETAILS_ENABLED,r1_0.ADMIN_EVENTS_ENABLED,r1_0.ADMIN_THEME,r1_0.ALLOW_USER_MANAGED_ACCESS,r1_0.BROWSER_FLOW,r1_0.CLIENT_AUTH_FLOW,r1_0.DEFAULT_LOCALE,r1_0.DEFAULT_ROLE,r1_0.DIRECT_GRANT_FLOW,r1_0.DOCKER_AUTH_FLOW,r1_0.DUPLICATE_EMAILS_ALLOWED,r1_0.EDIT_USERNAME_ALLOWED,r1_0.EMAIL_THEME,r1_0.ENABLED,r1_0.EVENTS_ENABLED,r1_0.EVENTS_EXPIRATION,r1_0.INTERNATIONALIZATION_ENABLED,r1_0.LOGIN_THEME,r1_0.LOGIN_WITH_EMAIL_ALLOWED,r1_0.MASTER_ADMIN_CLIENT,r1_0.NAME,r1_0.NOT_BEFORE,r1_0.OFFLINE_SESSION_IDLE_TIMEOUT,r1_0.OTP_POLICY_ALG,r1_0.OTP_POLICY_DIGITS,r1_0.OTP_POLICY_COUNTER,r1_0.OTP_POLICY_WINDOW,r1_0.OTP_POLICY_PERIOD,r1_0.OTP_POLICY_TYPE,r1_0.PASSWORD_POLICY,r1_0.REFRESH_TOKEN_MAX_REUSE,r1_0.REGISTRATION_ALLOWED,r1_0.REG_EMAIL_AS_USERNAME,r1_0.REGISTRATION_FLOW,r1_0.REMEMBER_ME,r1_0.RESET_CREDENTIALS_FLOW,r1_0.RESET_PASSWORD_ALLOWED,r1_0.REVOKE_REFRESH_TOKEN,r1_0.SSL_REQUIRED,r1_0.SSO_IDLE_TIMEOUT,r1_0.SSO_IDLE_TIMEOUT_REMEMBER_ME,r1_0.SSO_MAX_LIFESPAN,r1_0.SSO_MAX_LIFESPAN_REMEMBER_ME,r1_0.VERIFY_EMAIL,a1_0.REALM_ID,a1_0.NAME,a1_0.VALUE from REALM r1_0 left join REALM_ATTRIBUTE a1_0 on r1_0.ID=a1_0.REALM_ID where r1_0.ID=$1
docker-postgres-1  | 2023-12-03 09:57:38.352 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:57:38.366 UTC [219] LOG:  execute S_58: select c1_0.REALM_ID,c1_0.ID,c1_0.NAME,c1_0.PARENT_ID,c1_0.PROVIDER_ID,c1_0.PROVIDER_TYPE,c1_0.SUB_TYPE from COMPONENT c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-03 09:57:38.366 UTC [219] DETAIL:  parameters: $1 = 'fkh-customers-sample'
docker-postgres-1  | 2023-12-03 09:57:38.370 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:57:38.370 UTC [219] DETAIL:  parameters: $1 = 'a9082ecf-936e-4994-9617-31aa8688331c'
docker-postgres-1  | 2023-12-03 09:57:38.373 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:57:38.373 UTC [219] DETAIL:  parameters: $1 = '2e16262a-a140-45f0-9675-1f285d35f590'
docker-postgres-1  | 2023-12-03 09:57:38.375 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:57:38.375 UTC [219] DETAIL:  parameters: $1 = '666788fe-7de5-4e6b-88a2-c081b3115c7e'
docker-postgres-1  | 2023-12-03 09:57:38.380 UTC [219] LOG:  execute S_45: select c1_0.COMPONENT_ID,c1_0.ID,c1_0.NAME,c1_0.VALUE from COMPONENT_CONFIG c1_0 where c1_0.COMPONENT_ID=$1
docker-postgres-1  | 2023-12-03 09:57:38.380 UTC [219] DETAIL:  parameters: $1 = '2bc03384-1ded-491c-9688-eda0f8a748ea'
docker-postgres-1  | 2023-12-03 09:57:38.391 UTC [219] LOG:  execute <unnamed>: insert into CLIENT_INITIAL_ACCESS (COUNT,EXPIRATION,REALM_ID,REMAINING_COUNT,TIMESTAMP,ID) values ($1,$2,$3,$4,$5,$6)
docker-postgres-1  | 2023-12-03 09:57:38.391 UTC [219] DETAIL:  parameters: $1 = '5', $2 = '5', $3 = 'fkh-customers-sample', $4 = '5', $5 = '1701597458', $6 = '04e6d175-2b64-4b8f-913a-1e8af9a57202'
docker-postgres-1  | 2023-12-03 09:57:38.396 UTC [219] LOG:  execute S_1: COMMIT


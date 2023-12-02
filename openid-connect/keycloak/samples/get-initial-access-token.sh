# Request:
curl --location 'http://localhost:8080/realms/master/protocol/openid-connect/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'client_id=admin-cli' \
--data-urlencode 'username=admin' \
--data-urlencode 'password=password' \
--data-urlencode 'grant_type=password'


# Response:
{
    "access_token": "{{ access_token }}",
    "expires_in": 60,
    "refresh_expires_in": 1800,
    "refresh_token": "{{ refresh_token }}",
    "token_type": "Bearer",
    "not-before-policy": 0,
    "session_state": "c4916af4-0109-41b2-96ae-67fe8e1b262f",
    "scope": "email profile"
}


# DB Queries

docker-postgres-1  | 2023-12-02 20:32:41.007 UTC [30] LOG:  execute <unnamed>: BEGIN
docker-postgres-1  | 2023-12-02 20:32:41.007 UTC [30] LOG:  execute <unnamed>: select c1_0.ID from CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-02 20:32:41.007 UTC [30] DETAIL:  parameters: $1 = 'admin-cli', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-02 20:32:41.014 UTC [30] LOG:  execute <unnamed>: select c1_0.ID,c1_0.ALWAYS_DISPLAY_IN_CONSOLE,c1_0.BASE_URL,c1_0.BEARER_ONLY,c1_0.CLIENT_AUTHENTICATOR_TYPE,c1_0.CLIENT_ID,c1_0.CONSENT_REQUIRED,c1_0.DESCRIPTION,c1_0.DIRECT_ACCESS_GRANTS_ENABLED,c1_0.ENABLED,c1_0.FRONTCHANNEL_LOGOUT,c1_0.FULL_SCOPE_ALLOWED,c1_0.IMPLICIT_FLOW_ENABLED,c1_0.MANAGEMENT_URL,c1_0.NAME,c1_0.NODE_REREG_TIMEOUT,c1_0.NOT_BEFORE,c1_0.PROTOCOL,c1_0.PUBLIC_CLIENT,c1_0.REALM_ID,c1_0.REGISTRATION_TOKEN,c1_0.ROOT_URL,c1_0.SECRET,c1_0.SERVICE_ACCOUNTS_ENABLED,c1_0.STANDARD_FLOW_ENABLED,c1_0.SURROGATE_AUTH_REQUIRED from CLIENT c1_0 where c1_0.ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.014 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.020 UTC [30] LOG:  execute <unnamed>: select a1_0.CLIENT_ID,a1_0.NAME,a1_0.VALUE from CLIENT_ATTRIBUTES a1_0 where a1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.020 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.024 UTC [30] LOG:  execute <unnamed>: select a1_0.CLIENT_ID,a1_0.BINDING_NAME,a1_0.FLOW_ID from CLIENT_AUTH_FLOW_BINDINGS a1_0 where a1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.024 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.027 UTC [30] LOG:  execute <unnamed>: select r1_0.CLIENT_ID,r1_0.VALUE from REDIRECT_URIS r1_0 where r1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.027 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.034 UTC [30] LOG:  execute <unnamed>: select w1_0.CLIENT_ID,w1_0.VALUE from WEB_ORIGINS w1_0 where w1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.034 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.038 UTC [30] LOG:  execute <unnamed>: select s1_0.CLIENT_ID,s1_0.ROLE_ID from SCOPE_MAPPING s1_0 where s1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.038 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.043 UTC [30] LOG:  execute <unnamed>: select p1_0.CLIENT_ID,p1_0.ID,p1_0.CLIENT_SCOPE_ID,p1_0.NAME,p1_0.PROTOCOL,p1_0.PROTOCOL_MAPPER_NAME from PROTOCOL_MAPPER p1_0 where p1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.043 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.049 UTC [30] LOG:  execute <unnamed>: select r1_0.CLIENT_ID,r1_0.NAME,r1_0.VALUE from CLIENT_NODE_REGISTRATIONS r1_0 where r1_0.CLIENT_ID=$1
docker-postgres-1  | 2023-12-02 20:32:41.049 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:41.056 UTC [30] LOG:  execute <unnamed>: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-02 20:32:41.056 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8', $2 = 't'
docker-postgres-1  | 2023-12-02 20:32:41.069 UTC [30] LOG:  execute <unnamed>: select c1_0.SCOPE_ID from CLIENT_SCOPE_CLIENT c1_0 where c1_0.CLIENT_ID=$1 and c1_0.DEFAULT_SCOPE=$2
docker-postgres-1  | 2023-12-02 20:32:41.069 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8', $2 = 'f'
docker-postgres-1  | 2023-12-02 20:32:41.139 UTC [30] LOG:  execute <unnamed>: select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT,u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME from USER_ENTITY u1_0 where u1_0.USERNAME=$1 and u1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-02 20:32:41.139 UTC [30] DETAIL:  parameters: $1 = 'admin', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-02 20:32:41.216 UTC [30] LOG:  execute <unnamed>: select c1_0.ID,c1_0.CREATED_DATE,c1_0.CREDENTIAL_DATA,c1_0.PRIORITY,c1_0.SALT,c1_0.SECRET_DATA,c1_0.TYPE,c1_0.USER_ID,c1_0.USER_LABEL from CREDENTIAL c1_0 where c1_0.USER_ID=$1 order by c1_0.PRIORITY
docker-postgres-1  | 2023-12-02 20:32:41.216 UTC [30] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-02 20:32:41.597 UTC [30] LOG:  execute <unnamed>: select a1_0.USER_ID,a1_0.ID,a1_0.NAME,a1_0.VALUE from USER_ATTRIBUTE a1_0 where a1_0.USER_ID = any ($1)
docker-postgres-1  | 2023-12-02 20:32:41.597 UTC [30] DETAIL:  parameters: $1 = '{9887e9ac-640c-4d63-aab7-18a0b8d651fc,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL}'
docker-postgres-1  | 2023-12-02 20:32:41.616 UTC [30] LOG:  execute <unnamed>: select r1_0.USER_ID,r1_0.REQUIRED_ACTION from USER_REQUIRED_ACTION r1_0 where r1_0.USER_ID = any ($1)
docker-postgres-1  | 2023-12-02 20:32:41.616 UTC [30] DETAIL:  parameters: $1 = '{9887e9ac-640c-4d63-aab7-18a0b8d651fc,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL}'
docker-postgres-1  | 2023-12-02 20:32:42.318 UTC [30] LOG:  execute <unnamed>: select c1_0.ID from CLIENT_SCOPE c1_0 where c1_0.REALM_ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.318 UTC [30] DETAIL:  parameters: $1 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-02 20:32:42.360 UTC [30] LOG:  execute <unnamed>: select u1_0.GROUP_ID from USER_GROUP_MEMBERSHIP u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.360 UTC [30] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-02 20:32:42.401 UTC [30] LOG:  execute <unnamed>: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.401 UTC [30] DETAIL:  parameters: $1 = '9887e9ac-640c-4d63-aab7-18a0b8d651fc'
docker-postgres-1  | 2023-12-02 20:32:42.405 UTC [30] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.405 UTC [30] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d'
docker-postgres-1  | 2023-12-02 20:32:42.412 UTC [30] LOG:  execute <unnamed>: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.412 UTC [30] DETAIL:  parameters: $1 = 'c17bdf60-8d31-4270-954f-86657807832d'
docker-postgres-1  | 2023-12-02 20:32:42.448 UTC [30] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.448 UTC [30] DETAIL:  parameters: $1 = '95f88019-db86-4b67-b948-7ce034a6aec7'
docker-postgres-1  | 2023-12-02 20:32:42.453 UTC [30] LOG:  execute <unnamed>: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.453 UTC [30] DETAIL:  parameters: $1 = '95f88019-db86-4b67-b948-7ce034a6aec7'
docker-postgres-1  | 2023-12-02 20:32:42.460 UTC [30] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.460 UTC [30] DETAIL:  parameters: $1 = 'e174e66d-1219-4cf1-b7f6-b53b2229ad96'
docker-postgres-1  | 2023-12-02 20:32:42.469 UTC [30] LOG:  execute <unnamed>: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.469 UTC [30] DETAIL:  parameters: $1 = 'e174e66d-1219-4cf1-b7f6-b53b2229ad96'
docker-postgres-1  | 2023-12-02 20:32:42.473 UTC [30] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.ID=$1
docker-postgres-1  | 2023-12-02 20:32:42.473 UTC [30] DETAIL:  parameters: $1 = '6329d074-fbbe-4e3e-afd5-f138baf6da20'
docker-postgres-1  | 2023-12-02 20:32:42.476 UTC [30] LOG:  execute <unnamed>: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.476 UTC [30] DETAIL:  parameters: $1 = '6329d074-fbbe-4e3e-afd5-f138baf6da20'
docker-postgres-1  | 2023-12-02 20:32:42.488 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.488 UTC [30] DETAIL:  parameters: $1 = 'cf9cd115-13e1-48aa-96aa-3730b4317369'
docker-postgres-1  | 2023-12-02 20:32:42.511 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.511 UTC [30] DETAIL:  parameters: $1 = 'cde18285-f4ef-4039-a37c-d16c1874577f'
docker-postgres-1  | 2023-12-02 20:32:42.521 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.521 UTC [30] DETAIL:  parameters: $1 = '79ebbde1-7004-47af-99c6-00db99ce69f3'
docker-postgres-1  | 2023-12-02 20:32:42.523 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.523 UTC [30] DETAIL:  parameters: $1 = '15e68a6e-9366-45c2-bdc1-9466678af30a'
docker-postgres-1  | 2023-12-02 20:32:42.529 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.529 UTC [30] DETAIL:  parameters: $1 = 'f2f8698a-bcdd-4ebc-a9a2-76d96272f1c8'
docker-postgres-1  | 2023-12-02 20:32:42.536 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.536 UTC [30] DETAIL:  parameters: $1 = 'eead3eb8-c5c8-4320-a513-3b4771be7554'
docker-postgres-1  | 2023-12-02 20:32:42.541 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.541 UTC [30] DETAIL:  parameters: $1 = '026d9043-11b2-4a2f-8d49-74d1e2f84878'
docker-postgres-1  | 2023-12-02 20:32:42.545 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.545 UTC [30] DETAIL:  parameters: $1 = 'f6b377d5-4c8b-4e09-8bf0-8608f9b6a1c7'
docker-postgres-1  | 2023-12-02 20:32:42.550 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.550 UTC [30] DETAIL:  parameters: $1 = '1748567d-40e2-4c68-9e6a-75d244bebb2d'
docker-postgres-1  | 2023-12-02 20:32:42.555 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.555 UTC [30] DETAIL:  parameters: $1 = '1f5dbfbc-069b-479c-a237-15594dae3a1f'
docker-postgres-1  | 2023-12-02 20:32:42.559 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.559 UTC [30] DETAIL:  parameters: $1 = '636e0a46-c7f5-4042-85e8-292539fb6511'
docker-postgres-1  | 2023-12-02 20:32:42.563 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.563 UTC [30] DETAIL:  parameters: $1 = '454bf129-10d7-401e-b729-90d37f075be6'
docker-postgres-1  | 2023-12-02 20:32:42.570 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.570 UTC [30] DETAIL:  parameters: $1 = '1942a410-6f18-4734-84bc-87819e7e7411'
docker-postgres-1  | 2023-12-02 20:32:42.577 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.577 UTC [30] DETAIL:  parameters: $1 = 'edd004b9-a074-4eec-8696-db62f20cc2a2'
docker-postgres-1  | 2023-12-02 20:32:42.585 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.585 UTC [30] DETAIL:  parameters: $1 = 'b091b4c3-ba75-49bb-8eca-6de570e90603'
docker-postgres-1  | 2023-12-02 20:32:42.591 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.591 UTC [30] DETAIL:  parameters: $1 = '1c8077b2-8802-4b7c-95d3-c69dc32984a1'
docker-postgres-1  | 2023-12-02 20:32:42.595 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.595 UTC [30] DETAIL:  parameters: $1 = 'f8a31399-fbff-4666-8313-9d350d337b78'
docker-postgres-1  | 2023-12-02 20:32:42.601 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.601 UTC [30] DETAIL:  parameters: $1 = '9883ab18-a89c-4ab6-ab47-21e15a1eacb6'
docker-postgres-1  | 2023-12-02 20:32:42.607 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.607 UTC [30] DETAIL:  parameters: $1 = 'ebfa9e99-87c2-4ba3-ac37-080501a1b585'
docker-postgres-1  | 2023-12-02 20:32:42.613 UTC [30] LOG:  execute S_3: select c1_0.COMPOSITE,c1_1.ID,c1_1.CLIENT,c1_1.CLIENT_REALM_CONSTRAINT,c1_1.CLIENT_ROLE,c1_1.DESCRIPTION,c1_1.NAME,c1_1.REALM_ID from COMPOSITE_ROLE c1_0 join KEYCLOAK_ROLE c1_1 on c1_1.ID=c1_0.CHILD_ROLE where c1_0.COMPOSITE=$1
docker-postgres-1  | 2023-12-02 20:32:42.613 UTC [30] DETAIL:  parameters: $1 = '43828505-af6c-4c17-bd85-d6eaa89576f2'
docker-postgres-1  | 2023-12-02 20:32:42.625 UTC [30] LOG:  execute <unnamed>: select r1_0.ID,r1_0.CLIENT,r1_0.CLIENT_REALM_CONSTRAINT,r1_0.CLIENT_ROLE,r1_0.DESCRIPTION,r1_0.NAME,r1_0.REALM_ID from KEYCLOAK_ROLE r1_0 where r1_0.CLIENT=$1 order by r1_0.NAME
docker-postgres-1  | 2023-12-02 20:32:42.625 UTC [30] DETAIL:  parameters: $1 = '2a26e8e8-aa6f-4695-b680-2f133e3b29a8'
docker-postgres-1  | 2023-12-02 20:32:42.755 UTC [30] LOG:  execute S_2: COMMIT



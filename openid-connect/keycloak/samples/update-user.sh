# Request
curl --location --request PUT 'http://localhost:8080/admin/realms/fkh-customers-sample/users/4fee64a2-c356-4459-9d58-100bd3b3f8c6' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer {{ access_token }}' \
--data-raw '{
    "id": "4fee64a2-c356-4459-9d58-100bd3b3f8c6",
    "createdTimestamp": 1588881160516,
    "username": "majormajormajor",
    "enabled": true,
    "totp": false,
    "emailVerified": true,
    "firstName": "Major Major",
    "lastName": "Major",
    "email": "majormajormajor@lonelysoul.com",
    "disableableCredentialTypes": [],
    "requiredActions": [],
    "federatedIdentities": [],
    "notBefore": 0,
    "access": {
        "manageGroupMembership": true,
        "view": true,
        "mapRoles": true,
        "impersonate": true,
        "manage": true
    }
}'


# Response
HTTP 204


# DB Queries
docker-postgres-1  | 2023-12-03 10:07:20.291 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 10:07:20.293 UTC [219] LOG:  execute <unnamed>: select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT,u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME from USER_ENTITY u1_0 where u1_0.ID=$1
docker-postgres-1  | 2023-12-03 10:07:20.293 UTC [219] DETAIL:  parameters: $1 = '4fee64a2-c356-4459-9d58-100bd3b3f8c6'
docker-postgres-1  | 2023-12-03 10:07:20.295 UTC [219] LOG:  execute <unnamed>: select a1_0.USER_ID,a1_0.ID,a1_0.NAME,a1_0.VALUE from USER_ATTRIBUTE a1_0 where a1_0.USER_ID = any ($1)
docker-postgres-1  | 2023-12-03 10:07:20.295 UTC [219] DETAIL:  parameters: $1 = '{4fee64a2-c356-4459-9d58-100bd3b3f8c6,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL}'
docker-postgres-1  | 2023-12-03 10:07:20.298 UTC [219] LOG:  execute <unnamed>: select r1_0.USER_ID,r1_0.REQUIRED_ACTION from USER_REQUIRED_ACTION r1_0 where r1_0.USER_ID = any ($1)
docker-postgres-1  | 2023-12-03 10:07:20.298 UTC [219] DETAIL:  parameters: $1 = '{4fee64a2-c356-4459-9d58-100bd3b3f8c6,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL}'
docker-postgres-1  | 2023-12-03 10:07:20.301 UTC [219] LOG:  execute <unnamed>: update USER_ENTITY set CREATED_TIMESTAMP=$1,EMAIL=$2,EMAIL_CONSTRAINT=$3,EMAIL_VERIFIED=$4,ENABLED=$5,FEDERATION_LINK=$6,FIRST_NAME=$7,LAST_NAME=$8,NOT_BEFORE=$9,REALM_ID=$10,SERVICE_ACCOUNT_CLIENT_LINK=$11,USERNAME=$12 where ID=$13
docker-postgres-1  | 2023-12-03 10:07:20.301 UTC [219] DETAIL:  parameters: $1 = '1701597201824', $2 = 'majormajormajor@lonelysoul.com', $3 = 'majormajormajor@lonelysoul.com', $4 = 't', $5 = 't', $6 = NULL, $7 = 'Major Major', $8 = 'Major', $9 = '0', $10 = 'fkh-customers-sample', $11 = NULL, $12 = 'majormajormajor', $13 = '4fee64a2-c356-4459-9d58-100bd3b3f8c6'
docker-postgres-1  | 2023-12-03 10:07:20.304 UTC [219] LOG:  execute S_1: COMMIT



# Request
curl --location 'http://localhost:8080/admin/realms/fkh-customers-sample/users/4fee64a2-c356-4459-9d58-100bd3b3f8c6' \
--header 'Authorization: Bearer {{ access_token }}'


# Response
{
    "id": "4fee64a2-c356-4459-9d58-100bd3b3f8c6",
    "createdTimestamp": 1701597201824,
    "username": "majormajormajor",
    "enabled": true,
    "totp": false,
    "emailVerified": true,
    "firstName": "Major",
    "lastName": "Major",
    "email": "majormajormajormajor@lonelysoul.com",
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
}


# DB Queries

docker-postgres-1  | 2023-12-03 10:02:43.641 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 10:02:43.644 UTC [219] LOG:  execute <unnamed>: select f1_0.IDENTITY_PROVIDER,f1_0.USER_ID,f1_0.REALM_ID,f1_0.TOKEN,f1_0.FEDERATED_USER_ID,f1_0.FEDERATED_USERNAME from FEDERATED_IDENTITY f1_0 where f1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 10:02:43.644 UTC [219] DETAIL:  parameters: $1 = '4fee64a2-c356-4459-9d58-100bd3b3f8c6'
docker-postgres-1  | 2023-12-03 10:02:43.648 UTC [219] LOG:  execute <unnamed>: select b1_0.IDENTITY_PROVIDER,b1_0.USER_ID,b1_0.BROKER_USER_ID,b1_0.BROKER_USERNAME,b1_0.REALM_ID,b1_0.STORAGE_PROVIDER_ID,b1_0.TOKEN from BROKER_LINK b1_0 where b1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 10:02:43.648 UTC [219] DETAIL:  parameters: $1 = '4fee64a2-c356-4459-9d58-100bd3b3f8c6'
docker-postgres-1  | 2023-12-03 10:02:43.665 UTC [219] LOG:  execute S_1: COMMIT

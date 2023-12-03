# Request
curl --location 'http://localhost:8080/admin/realms/master/users' \
--header 'Authorization: Bearer {{ access_token }}'


# Response
[
    {
        "id": "9887e9ac-640c-4d63-aab7-18a0b8d651fc",
        "createdTimestamp": 1701075729849,
        "username": "admin",
        "enabled": true,
        "totp": false,
        "emailVerified": false,
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {
            "manageGroupMembership": true,
            "view": true,
            "mapRoles": true,
            "impersonate": true,
            "manage": true
        }
    }
]


# DB Queries
docker-postgres-1  | 2023-12-03 09:38:51.677 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 09:38:51.678 UTC [219] LOG:  execute <unnamed>: select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT,u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME from USER_ENTITY u1_0 where u1_0.SERVICE_ACCOUNT_CLIENT_LINK is null and u1_0.REALM_ID=$1 order by u1_0.USERNAME offset $2 rows fetch first $3 rows only
docker-postgres-1  | 2023-12-03 09:38:51.678 UTC [219] DETAIL:  parameters: $1 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $2 = '0', $3 = '100'
docker-postgres-1  | 2023-12-03 09:38:51.685 UTC [219] LOG:  execute S_1: COMMIT



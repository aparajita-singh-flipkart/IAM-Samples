# Request
curl --location 'http://localhost:8080/admin/realms/master/users' \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhRV9MTU9RMU9ZUHJfQUhDbUpuNExmZ3piWUtsUFBWZ2dkZURiM3BpZ193In0.eyJleHAiOjE3MDE1OTY3MTYsImlhdCI6MTcwMTU5NjY1NiwianRpIjoiODEzNWI3NmQtOTE0Mi00MGZkLTkxMmMtMmVlNzA4M2JkYmEyIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJzdWIiOiI5ODg3ZTlhYy02NDBjLTRkNjMtYWFiNy0xOGEwYjhkNjUxZmMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJhZG1pbi1jbGkiLCJzZXNzaW9uX3N0YXRlIjoiYjE3YjkwMjItMjhhOC00OTk4LWI1YTctZTgxZDc5NWEwNzhkIiwiYWNyIjoiMSIsInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6ImIxN2I5MDIyLTI4YTgtNDk5OC1iNWE3LWU4MWQ3OTVhMDc4ZCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4ifQ.PvxqnvAD1xf41bFjJMSSstaiBFatlN2VOyDorMKLPRQcajEKa4KwAnylrum-UvglQj_8T1bFSOUcyQ9IKmitkJ-kNdVN5zHwMKmCsQ7uOHQN8Zb_e09hSjHv9lViLf3ECvie5Qv0ywMkj_rmvIZqgETzRlkCnWrRAbvazIWiFPhGaLLVGePN80okn8o4smPf1UC9H2JgGEtuLhotTY24AImBNYVL-yQdP2Cd6YeGsMUWV0KaRuC_dH2TbwgHW2wN_n7tOAhFWs0M_fOnY9_EZTYZY1geq-kVPw6pajIVTzCDm7iIm_b0PSsWosEAkVaNEBbgeISKm7ogGGZLZzKDIQ' \
--data-raw '{
        "createdTimestamp": 1588880747548,
        "username": "majormajormajor",
        "enabled": true,
        "totp": false,
        "emailVerified": true,
        "firstName": "Major",
        "lastName": "Major",
        "email": "majormajormajormajor@lonelysoul.com",
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {
            "manageGroupMembership": true,
            "view": true,
            "mapRoles": true,
            "impersonate": true,
            "manage": true
        },
        "realmRoles": [	"mb-user" ]
    }'


# Response
HTTP 201


# DB Queries
docker-postgres-1  | 2023-12-03 09:44:21.268 UTC [219] LOG:  execute S_35: BEGIN
docker-postgres-1  | 2023-12-03 09:44:21.271 UTC [219] LOG:  execute <unnamed>: select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT,u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME from USER_ENTITY u1_0 where u1_0.USERNAME=$1 and u1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:44:21.271 UTC [219] DETAIL:  parameters: $1 = 'majormajormajor', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:44:21.281 UTC [219] LOG:  execute <unnamed>: select u1_0.ID,u1_0.CREATED_TIMESTAMP,u1_0.EMAIL,u1_0.EMAIL_CONSTRAINT,u1_0.EMAIL_VERIFIED,u1_0.ENABLED,u1_0.FEDERATION_LINK,u1_0.FIRST_NAME,u1_0.LAST_NAME,u1_0.NOT_BEFORE,u1_0.REALM_ID,u1_0.SERVICE_ACCOUNT_CLIENT_LINK,u1_0.USERNAME from USER_ENTITY u1_0 where u1_0.EMAIL=$1 and u1_0.REALM_ID=$2
docker-postgres-1  | 2023-12-03 09:44:21.281 UTC [219] DETAIL:  parameters: $1 = 'majormajormajormajor@lonelysoul.com', $2 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195'
docker-postgres-1  | 2023-12-03 09:44:21.348 UTC [219] LOG:  execute <unnamed>: insert into USER_ENTITY (CREATED_TIMESTAMP,EMAIL,EMAIL_CONSTRAINT,EMAIL_VERIFIED,ENABLED,FEDERATION_LINK,FIRST_NAME,LAST_NAME,NOT_BEFORE,REALM_ID,SERVICE_ACCOUNT_CLIENT_LINK,USERNAME,ID) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
docker-postgres-1  | 2023-12-03 09:44:21.348 UTC [219] DETAIL:  parameters: $1 = '1701596661346', $2 = NULL, $3 = '2068bca9-7e18-4392-9d3b-8d3224738bdc', $4 = 'f', $5 = 'f', $6 = NULL, $7 = NULL, $8 = NULL, $9 = '0', $10 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $11 = NULL, $12 = 'majormajormajor', $13 = 'e4e7f407-68fd-4a70-b9a0-f953c33b0799'
docker-postgres-1  | 2023-12-03 09:44:21.353 UTC [219] LOG:  execute S_30: select u1_0.ROLE_ID from USER_ROLE_MAPPING u1_0 where u1_0.USER_ID=$1
docker-postgres-1  | 2023-12-03 09:44:21.353 UTC [219] DETAIL:  parameters: $1 = 'e4e7f407-68fd-4a70-b9a0-f953c33b0799'
docker-postgres-1  | 2023-12-03 09:44:21.355 UTC [219] LOG:  execute S_31: insert into USER_ROLE_MAPPING (ROLE_ID,USER_ID) values ($1,$2)
docker-postgres-1  | 2023-12-03 09:44:21.355 UTC [219] DETAIL:  parameters: $1 = '2cb1616a-f451-4d0c-9a57-83d46e3f7dce', $2 = 'e4e7f407-68fd-4a70-b9a0-f953c33b0799'
docker-postgres-1  | 2023-12-03 09:44:21.368 UTC [219] LOG:  execute <unnamed>: update USER_ENTITY set CREATED_TIMESTAMP=$1,EMAIL=$2,EMAIL_CONSTRAINT=$3,EMAIL_VERIFIED=$4,ENABLED=$5,FEDERATION_LINK=$6,FIRST_NAME=$7,LAST_NAME=$8,NOT_BEFORE=$9,REALM_ID=$10,SERVICE_ACCOUNT_CLIENT_LINK=$11,USERNAME=$12 where ID=$13
docker-postgres-1  | 2023-12-03 09:44:21.368 UTC [219] DETAIL:  parameters: $1 = '1701596661346', $2 = 'majormajormajormajor@lonelysoul.com', $3 = 'majormajormajormajor@lonelysoul.com', $4 = 't', $5 = 't', $6 = NULL, $7 = 'Major', $8 = 'Major', $9 = '0', $10 = 'd87b5dc5-5fc7-4a96-bcd9-0f99800c8195', $11 = NULL, $12 = 'majormajormajor', $13 = 'e4e7f407-68fd-4a70-b9a0-f953c33b0799'
docker-postgres-1  | 2023-12-03 09:44:21.371 UTC [219] LOG:  execute S_1: COMMIT



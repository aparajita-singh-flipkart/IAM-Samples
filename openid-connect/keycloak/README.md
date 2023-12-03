# Keycloak
Keycloak is an implementation of OpenId Connect.

## Installation
Install keycloak using docker-compose. Link: https://github.com/GoogleCloudPlatform/click-to-deploy/tree/master/docker/keycloak#use-a-persistent-data-volume

This is the docker-compose.yml used for the POC:

```yml
---
version: '3'

services:
  postgres:
    image: marketplace.gcr.io/google/postgresql13
    volumes:
      - postgres-db-volume:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: password
  keycloak:
    image: marketplace.gcr.io/google/keycloak20
    volumes:
      - keycloak-data-volume:/opt/keycloak/data
    command: start-dev
    environment:
        KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
        KC_DB_USERNAME: keycloak
        KC_DB_PASSWORD: password
        KEYCLOAK_ADMIN: admin
        KEYCLOAK_ADMIN_PASSWORD: password
    ports:
      - 8080:8080
    depends_on:
      - postgres
volumes:
  postgres-db-volume:
  keycloak-data-volume:
```

## Steps
### Setup
1. Get the access token whenever you get HTTP 401 error: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/get-initial-access-token.sh
2. Create a tenant using the add realm api: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/create-tenant.sh
3. Activate the tenant using the initial access token api: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/get-initial-access-token.sh
4. Create the admin user to manage identities within the tenant
5. Activate the admin user
6. View existing realms using the get realms api: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/get-realms.sh
7. For this POC, we will continue using the existing "admin-cli" user as the admin for managing customer info. In a production setup, a separate user would have been created to manage all entities within a tenant.
8. [Signup] Create a customer identity with their profile: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/create-user.sh
9. [Fetch Profile] View the created customer entity: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/get-user.sh
10. [Update Profile] Update the user's profile information: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/update-user.sh
11. List available authentication mechanisms: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/list-authenticators.sh
12. [Login] 





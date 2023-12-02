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
1. Get the initial access token using: https://github.com/aparajita-singh-flipkart/IAM-Samples/blob/main/openid-connect/keycloak/samples/get-initial-access-token.sh
2. 





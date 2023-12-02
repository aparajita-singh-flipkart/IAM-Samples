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

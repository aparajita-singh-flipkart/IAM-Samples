# ORY Sample Curls
## Create identity
```bash
curl --request POST -sL \
  --header "Authorization: Bearer ory_pat_xRKLsFEOUFQFVBjd6o3FQDifaLYhabGd" \
  --header "Content-Type: application/json" \
  --data '{
  "schema_id": "preset://phone",
  "traits": {
    "phone": "9999999999"
  }
}' http://127.0.0.1:4433/admin/identities
```

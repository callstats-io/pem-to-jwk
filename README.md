# PEM-to-JWK

## Usage
```
# Generate EC key
openssl ecparam -name prime256v1 -genkey > ecpriv.key
# SSLeay EC PEM key to JWK
cat ecpriv.key | pem-to-jwk > jwk.json
# PKCS8 EC PEM key to JWK
openssl pkcs8 -in ecpriv.key -inform pem -nocrypt -topk8 | pem-to-jwk > jwk.json
```

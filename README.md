# PEM-to-JWK

## Usage

openssl ecparam -name prime256v1 -genkey > ecpriv.key
cat ecpriv.key | pem-to-jwk > jwk.json
openssl pkcs8 -in ecpriv.key -inform pem -nocrypt -topk8 | pem-to-jwk > jwk.json

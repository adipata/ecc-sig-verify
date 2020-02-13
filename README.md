# ecc-sig-verify
Certificate eliptic curve signature verification

* Generate certificate
openssl ecparam -name secp521r1 -genkey -param_enc explicit -out private-key.pem
openssl req -new -x509 -key private-key.pem -out server.pem -days 730

*Convert to DER
openssl x509 -inform pem -outform der -in server.pem -out server.der
openssl pkcs8 -topk8 -inform PEM -outform DER -in private-key.pem -out openssl-private-key.der -nocrypt
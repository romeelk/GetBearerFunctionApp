# download public/private key as pfx
az keyvault secret download --file testcert.pfx --name testcert --vault-name vaultkvrk --encoding base64 


# public/private key in one file
openssl pkcs12 -in testcert.pfx  -out testcertpubpriv.pem -nodes 

# just the private key
openssl pkcs12 -in testcert.pfx -nocerts -nodes -out testcertkey.key

# now get the cert
openssl pkcs12 -in testcert.pfx -clcerts -nokeys -out testcert.pem

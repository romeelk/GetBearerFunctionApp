
import uuid
import jwt
import time
import json
import base64
import uuid
import time
import hashlib
import os

from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def base64_decode_url(data):
    value = data.replace('-', '+').replace('_', '/')
    value += '=' * (len(value) % 4)
    return str(base64.urlsafe_b64decode(value), 'utf-8')

def encode_base64_url(payload:bytes) ->str:
    
    encoded = str(base64.b64encode(payload), 'utf-8')
    return encoded.replace('=', '').replace('+', '-').replace('/', '_')
def get_claims(tenant_id, client_id) -> dict:
    ## aud = https://login.microsoftonline.com/ + Tenant ID + /v2.0
    aud = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"

    confidential_client_id = client_id; #client id 00000000-0000-0000-0000-000000000000
    jwt_to_aad_lifetime_in_seconds = 60 * 10; ## Ten minutes
    valid_from = int(time.time())
    valid_to =  int(time.time()) + jwt_to_aad_lifetime_in_seconds

    claims = {  
        "aud": aud ,
        "exp": valid_to ,
        "iss": confidential_client_id ,
        "jti": str(uuid.uuid1),
        "nbf": valid_from ,
        "sub": confidential_client_id 
    }
    return claims
    
def get_signed_client_assertion():

    absolute_path = os.path.dirname(__file__)
    print(absolute_path)
    relative_path = "testcertkey.key"
    full_path = os.path.join(absolute_path, relative_path)  
    private_key_pem = Path(full_path).read_text()
    
    rsa_key =  load_pem_private_key(private_key_pem.encode('utf-8'),password=None)
    public_key_path  = os.path.join(absolute_path, "testcert.pem")  
    print(public_key_path)
    x509_certificate = load_pem_x509_certificate(Path(public_key_path).read_text().encode())
  
    # print thumbprint
    # print(x509_certificate.fingerprint(algorithm=hashes.SHA1()).hex())
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "x5t": encode_base64_url(x509_certificate.signature)
    }

    tenant_id = str("0893480d-4a15-4aa8-b46b-75e6bf0a63f4")
    client_id = str("6467738c-c2b4-4d76-ba04-073f885c72e0")
    claims = get_claims(tenant_id=tenant_id,client_id=client_id)

    header_bytes = json.dumps(header,indent=4, default=str).encode('utf-8')   
    claims_bytes = json.dumps(claims, indent=4, default=str).encode('utf-8')
    token =  encode_base64_url(header_bytes) + "." + encode_base64_url(claims_bytes)

    signed_token =  rsa_key.sign(token.encode("UTF-8"), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),hashes.SHA256())

    signed_client_assertion = token + "." + encode_base64_url(signed_token)

    print(signed_client_assertion)
    return signed_client_assertion


    
header = get_signed_client_assertion()
import uuid
import jwt
import time
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decode_jwt_token(token):
    unverified_headers = jwt.get_unverified_header(token)
    x509_certificate = load_pem_x509_certificate(Path('./scripts/testcert.pem').read_text().encode()).public_key()
    return jwt.decode(token, key= x509_certificate,algorithms=unverified_headers["alg"], audience="https://login.microsoftonline.com")
   

def generate_jwt_with_private_key():
    expiration = 3600
    now = int(time.time())
    clientid = str(uuid.uuid1())
    print(clientid)
    payload = {
        "iss": clientid,
        "sub": clientid,
        "aud": "https://login.microsoftonline.com",
        "iat": now,
        "exp": now + expiration
    }
    private_key_pem = Path("./scripts/testcertkey.key").read_text()
    print(private_key_pem)
    private_key = load_pem_private_key(private_key_pem.encode('utf-8'),password=None)
    return jwt.encode(payload=payload, key= private_key,algorithm="RS256")
    

def generate_jwt_using_secret():
    expiration = 3600
    now = int(time.time())

    clientid = str(uuid.uuid1())
    print(clientid)
    payload = {
        "iss": clientid,
        "sub": clientid,
        "aud": "https://login.microsoftonline.com",
        "iat": now,
        "exp": now + expiration
    }
    print(payload)
    jwttoken  = jwt.encode(payload=payload,key="password",algorithm="HS256")

    print(jwttoken)

def verify_message(signature):
    private_key_pem = Path("./scripts/testcertkey.key").read_text()
    private_key = load_pem_private_key(private_key_pem.encode('utf-8'),password=None)

    public_key = private_key.public_key()
    public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
def sign_message_with_private_key(message:str):
    private_key_pem = Path("./scripts/testcertkey.key").read_text()
    private_key = load_pem_private_key(private_key_pem.encode('utf-8'),password=None)

    signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())
    return signature


jwt_token = generate_jwt_with_private_key()
print(jwt_token)
decoded_jwt = decode_jwt_token(jwt_token)
print(decoded_jwt)

message = b'Test signing this message'
hash = sign_message_with_private_key(message)
print(hash)

verify_message(hash)
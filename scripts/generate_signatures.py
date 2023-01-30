"""
    This Python script extracts the private/public key pair 
    from an Azure KeyVault cert.
    It also signs a sample message using the private key.
"""

import os
import sys
import json
import logging
import base64
from binascii import hexlify

from azure.keyvault.secrets import SecretClient
from azure.identity import AzureCliCredential
from cryptography.hazmat.primitives.serialization import pkcs12

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA


def export_private_key(pk, filename: str):
    print(f"About to export.. private key to: {filename}")
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()

    )

    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def export_public_key(public_key, filename: str):
    filename = filename + "_pub.pem"
    print(f"About to export public key to file {filename}")

    public_cer = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(filename, "w") as public_key_file:
        public_key_file.write(public_cer.decode())


def sign_message(key, message):
    hash = SHA256.new(message.encode())
    print(f"hash: {hash.digest().hex()}")
    signature = pkcs1_15.new(key).sign(hash)
    print('signature: {}'.format(signature.hex()))
    return signature


def verify_signature(public_key, message, signature):
    print("Verifying signature of original message...")
    hash = SHA256.new(message.encode())
    print('h: {}'.format(hash.digest().hex()))
    print('signature: {}'.format(signature.hex()))
    pkcs1_15.new(public_key).verify(hash, signature)


logger = logging.getLogger('certificatelogger')
logging.basicConfig(level=os.environ.get("LOGLEVEL", "ERROR"))

# Get the RSA private key of the certificate

certificate_name = input("Please enter the name of the Key Vault certificate: ")

kv_uri = "https://" + "vaultkvrk" + ".vault.azure.net"

logger.info("---> authenticating to Azure ... ")

credential = AzureCliCredential()
client = SecretClient(vault_url=kv_uri, credential=credential)

try:
    print("Attempting to get privte key..")
    retrieved_secret = client.get_secret(certificate_name)
    cert_bytes = base64.b64decode(retrieved_secret.value)
    private_key, public_cert, additional_certificates = pkcs12.load_key_and_certificates(data=cert_bytes, password=None)

    export_private_key(private_key, "testcert_priv.pem")

    ## generate SHA256 
    message = input("Enter a string to sign with private key: ")
    # load private key
    with open("testcert_priv.pem", "r") as private_key_file:
        exported_private_key = RSA.importKey(private_key_file.read())

    public_key = exported_private_key.public_key().export_key('PEM')

    export_public_key(private_key.public_key(), certificate_name)

    imported_public_key = RSA.import_key(public_key)

    signed_message = sign_message(exported_private_key, message)
    verify_signature(imported_public_key, message, signed_message)

except Exception as e:
    print("Woops an unexpected eror occured. Exiting script: " + str(e))
    sys.exit(1)

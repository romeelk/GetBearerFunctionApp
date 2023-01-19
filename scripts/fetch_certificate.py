import os
import sys
import json
import logging
from binascii import hexlify

from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.identity import AzureCliCredential

logger = logging.getLogger('certificatelogger')
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

# Use json.dumps(certificate_properties, indent=4,default=str to convert types no tserializable to str!!
def dump_cert_props_to_json(certificate: KeyVaultCertificate): 
        certificate_properties = {}
        try:
            certificate_info = certificate.__dict__["_properties"]

            for key in certificate_info.__dict__:
                if key == '_attributes':
                    attributes = certificate_info.__dict__[key].__dict__
                    print(f'Attributes type:{type(attributes)}')
                    certificate_properties.update(attributes)
                else:
                    certificate_properties[key] = certificate_info.__dict__[key]

            cert_json = json.dumps(certificate_properties, indent=4, default=str)
            print("About to output to file cert_props.json")
            # Writing to sample.json
            with open("cert_props.json", "w") as outfile:
                outfile.write(cert_json)
                        
        except Exception as e:
            print('Error' +str(e))
      

def print_cert_details(certificate: KeyVaultCertificate):
    print(f"Certificate with name '{certificate.name}' was found'.")

    print(f'Type: {type(certificate.properties.x509_thumbprint)}')
    # use hexify to get hex string or use 
    thumbprint_hexlify = hexlify(certificate.properties.x509_thumbprint).decode("utf-8")

    print(f"Certificate has thumbprint using hexlify library: {thumbprint_hexlify.upper()}")

    thumbprint = certificate.properties.x509_thumbprint.hex()

    print(f'Certificate has thumbprint using .hex() function: {thumbprint}')
    print(f'Certificate expires on {certificate.properties.expires_on}')

logger.info("----> Checking for KEY_VAULT_NAME env var ")
key_vault_name = os.environ.get("KEY_VAULT_NAME")
    
if key_vault_name == None:
    print("Please set environment var KEY_VAULT_NAME")
    sys.exit(1)

kv_uri = "https://" + key_vault_name + ".vault.azure.net"

logger.info("---> authenticating to Azure ... ")

credential = AzureCliCredential()
client = CertificateClient(vault_url=kv_uri, credential=credential)

while True:
    print(f"Retrieving your certificate from {key_vault_name}.")
    certificate_name = input("Input a name for your certificate > ")

    try:
        retrieved_certificate = client.get_certificate(certificate_name)
        if retrieved_certificate != None:
            break
    except Exception as e: 
        print(f"Oops could not find certificate in KeyVault {key_vault_name} named {certificate_name}")
        logger.error(f'---> Exception caught whilst fetching certificate: {e}')

dump_cert_props_to_json(retrieved_certificate)

print_cert_details(retrieved_certificate)

print(" done.")
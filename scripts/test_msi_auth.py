import logging
import os
from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.identity import ManagedIdentityCredential

logger = logging.getLogger('certificatelogger')
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

credential = ManagedIdentityCredential(additionally_allowed_tenants="*")
key_vault_name = "vaultkvrk"
kv_uri = "https://" + key_vault_name + ".vault.azure.net"
client = CertificateClient(vault_url=kv_uri, credential=credential)

retrieved_certificate = client.get_certificate('testcert')

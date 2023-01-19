
import azure.functions as func

import logging
import os
from azure.keyvault.certificates import CertificateClient, KeyVaultCertificate
from azure.identity import ManagedIdentityCredential, AzureCliCredential

logger = logging.getLogger('azure')
logger.setLevel(logging.DEBUG)

def main(req: func.HttpRequest) -> func.HttpResponse:
    logger.info('Python HTTP trigger function processed a request.')
 
    logger.info(f'---> Checking app setting LocalDev:{os.getenv("LocalDev")}')

    local_dev = os.getenv("LocalDev")   
    msi_client_id = os.getenv("msi_client_id")

    if local_dev == "True":   
        logger.info('---> Attempting to authenticate with Azure CLI.')

        credential = AzureCliCredential()   
    else:
        credential = ManagedIdentityCredential(client_id=msi_client_id)        
    
    key_vault_name = os.getenv("key_vault_name")
    kv_uri = "https://" + key_vault_name + ".vault.azure.net"
    client = CertificateClient(vault_url=kv_uri, credential=credential)

    certificate = req.params.get('certificate')

    if certificate:
                  
        try:
            retrieved_certificate = client.get_certificate(certificate) 
            logger.info(f'---> Fetched cert{certificate} successfully')
            logger.info(f'---> Certificate will expire on {retrieved_certificate.properties.expires_on}')
            return func.HttpResponse(f"Succesfuly, fetched certificate {certificate}. This HTTP triggered function executed successfully.")
        except Exception as e: 
            logger.error(f'---> Exception caught whilst fetching certificate: {e}')
            return func.HttpResponse(
             f"Failed to process request. Error whilst fetching certificate {certificate}. Certificate was not found in Key Vault.",
             status_code=404
        )
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a certificate name in the query string or in the request body for a personalized response.",
             status_code=200
        )

    
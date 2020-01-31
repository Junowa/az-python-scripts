import base64
from OpenSSL import crypto
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

credential =  ManagedIdentityCredential()
secret_client = SecretClient(vault_url="https://coreauto-keyvault-dev.vault.azure.net/", credential=credential)

secret = secret_client.get_secret("sonarqube-dev0854863a-d060-4059-95a8-6ab9c70cf122")

print(secret.name)

p12 = crypto.load_pkcs12(base64.b64decode(secret.value))

# PEM formatted private key
print crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())

# PEM formatted certificate
print crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())

# PEM formatted CA certificate
cacerts=p12.get_ca_certificates()
for cacert in cacerts:
        print crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)
 #!/usr/bin/env python

"""
VM certificates refresh agent

This scripts:
- checks certificates renewal status in azure keyvault
- update local certificates and restart associated service if necessary

The script authenticates using Azure Syste with Managed Identies.

Azure System Managed Identies must be configured in the VM beforehand:
https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/tutorial-linux-vm-access-arm

System Managed Identity MUST be authorize in Azure Key Vault access policies:
https://docs.microsoft.com/en-us/azure/key-vault/managed-identity 

Create YAML Configuration file in ~/.config/cert-autorenew/config.yaml as follows:

---
# Number of days between certificate checks
check_interval: 1

# Specify number of days before expiration renewal must be perfomed
days_before_expiration: 7

# Certificates to monitor
certificates:
  - secret_name: sonarqube-dev0854863a-d060-4059-95a8-6ab9c70cf122
    vault_url: https://myteam-keyvault-dev.vault.azure.net/
    kpriv_localpath: /etc/ssl/sonar.priv
    kpub_localpath: /etc/ssl/sonar.pub
    restart_command: "systemctl restart sonarqube"
---

This script must be run as root to restart the service.
"""

import sys
import os
import stat
import time
import logging
import logging.handlers
import confuse
import base64
import subprocess
import pytz
from datetime import datetime, timedelta
from OpenSSL import crypto
from azure.identity import  ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient


class Certificate:
  """ Base Certificate class for certificate management """

  #TODO: private attributes/functions
  def __init__(self, secret_name, vault_url, kpriv_localpath, kpub_localpath, restart_command):
    self.secret_name = secret_name
    self.vault_url = vault_url
    self.kpriv_localpath = kpriv_localpath
    self.kpub_localpath = kpub_localpath
    self.restart_command = restart_command
    self.secret = self.get_secret_from_vault()
  

  def get_secret_from_vault(self):
    
    # Connect to vault
    credential =  ManagedIdentityCredential()
    secret_client = SecretClient(vault_url=self.vault_url, credential=credential)
    
    return secret_client.get_secret(self.secret_name)


  def is_renewable(self):

    utc=pytz.UTC

    if (self.secret.properties.expires_on.replace(tzinfo=utc)) >= (datetime.today()+timedelta(days=config['days_before_expiration'].get(int))).replace(tzinfo=utc):
      return False
    else:
      return True


  def renew(self):
    
    #TODO why vault_url is not a string
    logger.info("Extracting "+self.secret_name+ "from "+self.vault_url)

    p12 = crypto.load_pkcs12(base64.b64decode(self.secret.value))

    # PEM formatted private key
    kpriv = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
    update_localfile(self.kpriv_localpath, kpriv, readonly=True)

    # PEM formatted certificate
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
    #update_localfile(self.kpub_localpath)

    # PEM formatted CA certificate
    cacerts=p12.get_ca_certificates()
    # Concatenate clcert with cacerts
    for cacert in cacerts:
      cert = cert + crypto.dump_certificate(crypto.FILETYPE_PEM, cacert)
    
    update_localfile(self.kpub_localpath, cert)

    if self.restart_command:
      #TODO error management
      subprocess.call(self.restart_command.split())


def update_localfile(localpath, data, readonly=False):

  # Backup previous version
  if os.path.exists(localpath):
    os.rename(os.path.realpath(localpath), os.path.realpath(localpath)+".bk")

  with open(localpath, "w") as f: 
    f.write(data)

  # chmod 440
  if readonly is True:
    os.chmod(localpath, stat.S_IRUSR | stat.S_IRGRP)


def setup_logging():

  root = logging.getLogger("")
  root.setLevel(logging.WARNING)

  # if script is non-interactive
  if not sys.stderr.isatty():
    facility = logging.handlers.SysLogHandler.LOG_DAEMON
    loghandler = logging.handlers.SysLogHandler(address='/dev/log', facility=facility)
    loghandler.setFormatter(logging.Formatter(
        "{0}[{1}]: %(message)s".format(
            logger.name,
            os.getpid())))
    root.addHandler(loghandler)

  else:
    streamhandler = logging.StreamHandler()
    streamhandler.setFormatter(logging.Formatter(
        "%(levelname)s[%(name)s] %(message)s"))
    root.addHandler(streamhandler)


def setup_config():
  
  #TODO: add config data validation
  for cert in config['certificates']:
        certs_mgr.append(Certificate(
          secret_name=cert['secret_name'].get(str), 
          vault_url=cert['vault_url'].get(str), 
          kpriv_localpath=cert['kpriv_localpath'].get(str),
          kpub_localpath=cert['kpub_localpath'].get(str),
          restart_command=cert['restart_command'].get(str)))

def main():

  while True:
    for c in certs_mgr:
      if c.is_renewable():
        c.renew()

    time.sleep(config['check_interval'].get(int)*86400)


if __name__ == "__main__":

  # Setup global logger
  logger = logging.getLogger(os.path.splitext(os.path.basename(sys.argv[0]))[0])
  logger.setLevel(logging.INFO)
  setup_logging()

  # Init Certificate Manager
  certs_mgr = []
  config = confuse.Configuration(os.path.splitext(os.path.basename(sys.argv[0]))[0])
  setup_config()

  main()

  sys.exit(0)

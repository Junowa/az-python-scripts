#!/usr/bin/env python

"""Upload file to Azure Blob Storage."""
import os
import sys
import argparse
import logging
import logging.handlers
from azure.storage.blob import BlobClient
from azure.core.exceptions import AzureError

class CustomFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument("connection_string", type=str, help="connection string")
    parser.add_argument("container", type=str, help="container name")
    parser.add_argument("filepath", type=str, help="file to upload")
    parser.add_argument("blobname", type=str, help="blob name")
    parser.add_argument("--azstack", action="store_true",
                        help="enable compatibility with azurestack")

    return parser.parse_args()


# configure root LOGGER, children LOGGERs inherits then from root LOGGER
def setup_logging():

    root = logging.getLogger("")
    root.setLevel(logging.WARNING)

    # if script is non-interactive
    if not sys.stderr.isatty():
        facility = logging.handlers.SysLogHandler.LOG_DAEMON
        loghandler = logging.handlers.SysLogHandler(address='/dev/log', facility=facility)
        loghandler.setFormatter(logging.Formatter(
            "{0}[{1}]: %(message)s".format(
                LOGGER.name,
                os.getpid())))
        root.addHandler(loghandler)

    else:
        streamhandler = logging.StreamHandler()
        streamhandler.setFormatter(logging.Formatter(
            "%(levelname)s[%(name)s] %(message)s"))
        root.addHandler(streamhandler)


def upload(connection_string, container, filepath, blobname, headers):

    LOGGER.info("uploading to blob")
    blob = BlobClient.from_connection_string(
        connection_string, container_name=container,
        blob_name=blobname, headers=headers,
        connection_timeout=5, retry_total=3)

    try:
        with open(filepath, 'rb') as data:
            blob.upload_blob(data, overwrite=False)
    except AzureError as error:
        LOGGER.exception(error)


def main():

    args = parse_args()

    # Enable azurestack compatibility
    if args.azstack:
        headers = {'x-ms-version': '2017-04-17'}
    else:
        headers = {}

    LOGGER.info("starting")
    upload(args.connection_string, args.container, args.filepath, args.blobname, headers)


if __name__ == "__main__":

    LOGGER = logging.getLogger(os.path.splitext(os.path.basename(sys.argv[0]))[0])
    LOGGER.setLevel(logging.INFO)
    setup_logging()

    main()

    sys.exit(0)

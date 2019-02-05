import boto3
import json
import logging
import os
import re
import ast

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slackChannel']

HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext'].decode('utf-8')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    logger.info("Raw Message: " + str(event['Records'][0]['Sns']['Message'].strip()))
    raw_msg = ast.literal_eval(event['Records'][0]['Sns']['Message'].strip())
    message = json.loads(json.dumps(raw_msg[0]))
    
    if re.match(r".*(COMPLIANT)", message['title']):
        status = {"color": "good"}
    if re.match(r".*(NON_COMPLIANT)", message['title']):
        status = {"color": "danger"}
    if re.match(r".*(NOT_APPLICABLE)", message['title']):
        status = {"color": "warning"}

    message.update(status)
    slack_message = {
        'channel': SLACK_CHANNEL,
        'attachments': [message]
    }
    
    logger.info("Message: " + str(slack_message))

    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)

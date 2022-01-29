from json import dumps as json_dumps
from json import loads as json_loads
from boto3 import client as boto3_client
from urllib.parse import urlencode, parse_qsl
from urllib3 import PoolManager as urllib3_PoolManager
from urllib3.exceptions import NewConnectionError as urllib3_NewConnectionError
from base64 import urlsafe_b64encode
from hashlib import sha256
from re import sub as re_sub

http = urllib3_PoolManager()
sqs_client = boto3_client('sqs')
kms_client = boto3_client('kms')

QUEUE_URL = ...
SKILL_ID = ...
OAUTH_HOST = ...
AUTH_ENDPOINT = ...
TOKEN_ENDPOINT = ...

def create_secret():
   bytes_ = kms_client.generate_random(NumberOfBytes=40).get('Plaintext')
   sec = urlsafe_b64encode(bytes_).decode('utf-8')
   sec = re_sub('[^a-zA-Z0-9]+', '', sec)
   m = sha256(sec.encode('utf-8')).digest()
   challenge = urlsafe_b64encode(m).decode('utf-8').replace('=', '')
   return (challenge, sec)

def lambda_handler(event, context):

    headers = event.get('headers')
    if headers is None:
        return {
            'statusCode': 400,
            'body': json_dumps(event)
        }
    
    path = event.get('path')
    if path.endswith('/OAuth2-PKCE-proxy'):  # first endpoint
        queryStringParameters = event.get('queryStringParameters')
        requestContext = event.get('requestContext')
        redirect_uri = queryStringParameters.get('redirect_uri')
        s = redirect_uri.rfind('/')
        if redirect_uri[s+1:] != SKILL_ID:
            print('bad skill ID: {}'.format(redirect_uri[s+1:]))
            exit()

        tup = create_secret()
        queryStringParameters['code_challenge'] = tup[0]
        secret = tup[1]
        this_state = queryStringParameters.get('state')
        msgbdy = { 'secret': secret, 'state': this_state }
        response = sqs_client.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json_dumps(msgbdy),
            MessageGroupId=requestContext.get('requestId')
        )
        queryStringParameters['code_challenge_method'] = 'S256'
        return {
            'statusCode': 302,
            'headers': {'Location': AUTH_ENDPOINT + '?' + urlencode(queryStringParameters) }
        }

    elif path.endswith('/OAuth2-PKCE-proxy/token'):
        body = event.get('body')
        response = sqs_client.receive_message(
            QueueUrl=QUEUE_URL,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=1
        )
        messages = response.get('Messages')
        if messages is None or len(messages) == 0:
            print('Failed to read queue: {}'.format(messages))
            exit()
        for msg in messages:
            rh = msg.get('ReceiptHandle')
            msgbody = json_loads(msg.get('Body'))
            print('msgbody.state: {}'.format(msgbody.get('state')))
            secret = msgbody.get('secret')
            body_dict = dict(parse_qsl(body))
            body_dict['code_verifier'] = secret
            sqs_client.delete_message(QueueUrl=QUEUE_URL,
                ReceiptHandle=rh)
            break
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            encoded_body = urlencode(body_dict).encode('utf-8')
            r = http.request('POST', TOKEN_ENDPOINT, headers=headers, body=encoded_body)
        except urllib3_NewConnectionError:
            print("Connection failed.")
            return { 'statusCode': 404 }
        return {
            'statusCode': 200,
            'body': r.data
            }
    else:
        return {
            'statusCode': 404
            }


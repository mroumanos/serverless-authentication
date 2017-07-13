import os
import ldap
import json
import uuid, hashlib
import boto3
import time
from jwcrypto import jwk, jwt

def login(event, context):

    protocol = os.environ['protocol']
    hostname = os.environ['hostname']
    port = os.environ['port']
    binddn = os.environ['binddn']

    conn = ldap.initialize('{}://{}:{}'.format(protocol,hostname,port))

    conn.set_option(ldap.OPT_X_TLS_DEMAND, False)

    #
    # add data validation!
    #
    body = json.loads(event['body'])
    uid = body['uid']
    password = body['password']

    try:
        conn.bind_s(binddn.format(uid), password)

    except:
        return {
            "location": os.environ['loginurl'],
            "message" : "Your login failed !"
        }

    # you only get here if you were able to bind with correct uid/pw
    start = time.time()
    end = start + 86400
    jti = str(uuid.uuid1())

    #create claims
    claims = {
        'exp': end,
        'nbf': start,
        'iat': start,
        'iss': 'lambda.rft.geointservices.io',
        'aud': 'rft.geointservices.io',
        'prn': uid,
        'jti': jti
    }

    try:
        with open('login/key.json', 'rb') as file:
            key = jwk.JWK(**json.loads(file.read()))
            token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
            token.make_signed_token(key)

    except:
        return {
            "location": "https://login.rft.geointservices.io",
            "message": "Error JWT encryption"
        }

    dynamodb = boto3.resource('dynamodb')

    try:
        table = dynamodb.Table(os.environ['table'])
        item = {
            'jti': jti,
            'session': {
                'user': uid,
                'created_at': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(start)),
                'expires_at': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(end))
            }
        }
        table.put_item(Item=item)
    except:
        return {
            "location" : "https://login.rft.geointservices.io",
            "message" : "Error writing to Dynamo"
        }

    return {
        {
            "statusCode": 302,
            "headers": { "location": "https://6mnsa3wiff.execute-api.us-east-1.amazonaws.com/test",
                         "rft-gs-authorization" : "Bearer " + token.serialize() },
            "body": "You are logged in!"
        }
    }



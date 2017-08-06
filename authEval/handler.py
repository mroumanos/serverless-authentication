import re
import os
import json
import boto3
from botocore.exceptions import ClientError
from jwcrypto import jwk, jwt, jws

def auth(event, context):

    bodyTemplate = '[{0}] {1} ({2})'

    try:
        # retrieve cookie from requester
        token = event['headers']['X-rft-gs-authorization']

        # verify that the token
        with open('authEval/key.json', 'rb') as file:
            key = jwk.JWK(**json.loads(file.read()))
            verified = jwt.JWT(key=key, jwt=token)

    except KeyError as e:
        raise Exception(bodyTemplate.format(401, 'Unauthorized: no session cookie found', str(e)))

    except (jwk.InvalidJWKValue, jwk.InvalidJWKOperation, jwk.InvalidJWKUsage, jws.InvalidJWSSignature, jws.InvalidJWSObject, jws.InvalidJWSOperation) as e:
        raise Exception(bodyTemplate.format(401, 'Unauthorized: token not valid', str(e)))

    except:
        raise Exception(bodyTemplate.format(401, 'Unauthorized: unknown error', 'token=' + str(token) + ' event=' + str(event)))

    try:
        s3 = boto3.resource('s3')
        obj = s3.Object(os.environ['policyBucket'], '{}/{}'.format(os.environ['policyPath'],os.environ['policyFile']))
        policy = json.loads(obj.get()['Body'].read())
        print policy
        username = json.loads(verified.claims)['prn']
        print username
        print(policy[username])
        profile = policy[username] # will throw error if not there

    except ClientError as e:
        raise Exception(bodyTemplate.format(401, 'Unauthorized: bucket access error ({}/{})'.format(os.environ['policyBucket'],'{}/{}'.format(os.environ['policyPath'],os.environ['policyFile'])), str(e)))

    except KeyError as e:
        raise Exception(bodyTemplate.format(401, 'Unauthorized: username not whitelisted ({})'.format(username), str(e)))

    except:
        raise Exception(bodyTemplate.format(401, 'Unauthorized: unknown error', 'token=' + str(token) + ' event=' + str(event)))

    raise Exception(bodyTemplate.format(202, 'Authorized: welcome!', 'profile={} token={}'.format(profile,verified.claims)))

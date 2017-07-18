import re
import os
import json
import boto3
from botocore.exceptions import ClientError
from jwcrypto import jwk, jwt, jws

def auth(event, context):

    bodyTemplate = '{0}: {1} ({2})'

    try:
        # retrieve cookie from requester
        token = event['headers']['Cookie']

        # verify that the token
        with open('auth/key.json', 'rb') as file:
            key = jwk.JWK(**json.loads(file.read()))
            verified = jwt.JWT(key=key, jwt=token)

        # verify session token has been issued to dynamo table (optional)
        # dynamodb = boto3.resource('dynamodb')
        # claims = json.loads(verified.claims)
        # table = dynamodb.Table(os.environ['table'])
        # item = table.get_item(
        #     Key={
        #         'jti': claims['jti']
        #     }
        # )
        # if len(item['Item']) == 1 : # if no entries were found, it returns an empty list
        #     return { 'statusCode' : 202, 'body' : bodyTemplate.format('Authorized', 'welcome to RFT', str(verified.claims)) }
        # else:
        #     raise ClientError

    except KeyError as e:
        return {'statusCode' : 404, 'body' : bodyTemplate.format('Unauthorized', 'no session cookie found', str(e))}

    except (jwk.InvalidJWKValue, jwk.InvalidJWKOperation, jwk.InvalidJWKUsage, jws.InvalidJWSSignature, jws.InvalidJWSObject, jws.InvalidJWSOperation) as e:
        return {'statusCode' : 404, 'body' : bodyTemplate.format('Unauthorized', 'token not valid', str(e))}

    except ClientError as e:
        return {'statusCode' : 404, 'body' : bodyTemplate.format('Unauthorized', 'table entry not valid', str(e))}

    except:
        return {'statusCode': 404, 'body': bodyTemplate.format('Unauthorized', 'login error', 'unk')}

    return {'statusCode': 202, 'body': bodyTemplate.format('Authorized', 'welcome to RFT', str(verified.claims))}
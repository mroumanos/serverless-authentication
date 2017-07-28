import os
import ldap
import json
import uuid
import boto3
from botocore.exceptions import ClientError
import time
from jwcrypto import jwk, jwt, jws

def login(event, context):

    bodyTemplate = '{0}: {1} ({2})'
    protocol = os.environ['protocol']
    hostname = os.environ['hostname']
    port = os.environ['port']
    binddn = os.environ['binddn']

    conn = ldap.initialize('{}://{}:{}'.format(protocol,hostname,port))

    conn.set_option(ldap.OPT_X_TLS_DEMAND, False)

    #
    # add data validation!
    #

    uid = event['body']['uid']
    password = event['body']['password']

    # create claims
    start = time.time()
    end = start + 86400
    jti = str(uuid.uuid1())
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
        conn.bind_s(binddn.format(uid), password)

        with open('login/key.json', 'rb') as file:
            key = jwk.JWK(**json.loads(file.read()))
            token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
            token.make_signed_token(key)

        cookie_token = 'rft_gs_authorization={}; domain=rft.geointservices.io; expires={};'.format(token.serialize(),time.strftime('%a, %d %b %y %H:%M:%S',time.gmtime(end)))

    except ldap.LDAPError as e:
        return { 'location': 'https://' + os.environ['loginurl'], 'body' : bodyTemplate.format('Unauthorized', 'LDAP error', str(e)) }

    except (jwk.InvalidJWKValue, jwk.InvalidJWKOperation, jwk.InvalidJWKUsage, jws.InvalidJWSSignature, jws.InvalidJWSObject, jws.InvalidJWSOperation) as e:
        return { 'location': 'https://' + os.environ['loginurl'], 'body': bodyTemplate.format('Unauthorized', 'JWT error', str(e)) }

    except ClientError as e:
        return {'location': 'https://' + os.environ['loginurl'], 'body' : bodyTemplate.format('Unauthorized', 'Dynamo error', str(e)) }

    except:
        return { 'location': 'https://' + os.environ['loginurl'], 'body': 'Unknown error' }

    return { 'location': 'https://home.rft.geointservices.io', 'cookie': cookie_token }
# Serverless Authentication System
Custom AWS Lambda authentication system that uses JSON Web Token authentication for single sign-on applications

## Overview
All components of an authentication system are provided here. How the authentication is conducted is up to you:
 -> s3 -> static HTML page (login)
 -> serverless -> login (POST) -> assign http cookie
 ... browse ...
 -> serverless -> auth (GET) -> return 200 if valid and authenticated cookie

## Prequisites
[AWS account](www.aws.amazon.com)

[serverless](https://serverless.com/) or `npm install -g serverless`

## To-Dos
- [ ] Create tests
- [ ] Abstract authorizer as a class
- [ ] Abstract authentication method

# oauth2-pkce-proxy
Serverless AWS Account Linking proxy providing OAuth2 access to PKCE-only services

The repo provides general Python3 code for the Lambda, and exported JSON of the API Gateway (which is really simple).

![This is an image](/diag.svg)

Amazon KMS is used as source of the secret, and SQS stores the global variable of the secret between lambda invocations. I use the proxy to enable account linking for an Alexa skill because the ASK does not support PKCE.


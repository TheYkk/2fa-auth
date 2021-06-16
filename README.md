# 2fa-auth for k8s ingress external auth

This projects aims to make a middleware between your service and ingress.

Every ingress requests will sended to this middleware and check if the user has an auth cookie,
if has it will allow the request if not it will show the 2fa page 

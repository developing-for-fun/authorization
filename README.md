# Authorization

Example project for Spring Boot 3.2 OAuth2 Authorization Server

## Curls

```shell
curl --location 'http://localhost:8080/oauth2/token' \
--header 'Authorization: Basic c3dhZ2dlci1jbGllbnQ6c2VjcmV0' \
--form 'grant_type="client_credentials"'
```
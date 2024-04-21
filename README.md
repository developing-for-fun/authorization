# Authorization

Example project for Spring Boot 3.2 OAuth2 Authorization Server

## Example

### Client credentials flow auth token

Using `swagger-client`

```shell
curl --location 'http://localhost:8080/oauth2/token' \
--header 'Authorization: Basic c3dhZ2dlci1jbGllbnQ6c2VjcmV0' \
--form 'grant_type="client_credentials"'
```

Decoded auth jwt should be:

```json
{
  "sub": "swagger-client",
  "aud": "swagger-client",
  "nbf": 1713714133,
  "iss": "http://localhost:8080",
  "exp": 1713714433,
  "per": [
    "SWAGGER_R",
    "SWAGGER_W"
  ],
  "iat": 1713714133,
  "jti": "c9e81820-ea64-4297-90bc-e14784d2d474"
}
```
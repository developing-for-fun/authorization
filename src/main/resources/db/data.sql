insert into
  oauth2.oauth2_client (
    authorization_grant_types,
    client_authentication_methods,
    client_id,
    client_id_issued_at,
    client_name,
    client_secret,
    client_secret_expires_at,
    client_settings,
    redirect_uris,
    scopes,
    token_settings,
    id
  )
values
  (
    'client_credentials',
    'client_secret_post,client_secret_basic',
    'swagger-client',
    NULL,
    '6d165cb9-8f4d-4028-8936-239d31fc20a7',
    '{noop}secret',
    NULL,
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
    'http://localhost:8282/api',
    'swagger.write,swagger.read',
    '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}',
    '6d165cb9-8f4d-4028-8936-239d31fc20a7'
  );

insert into
  oauth2.oauth2_user (
    account_non_expired,
    account_non_locked,
    credentials_non_expired,
    enabled,
    password,
    username,
    id
  )
values
  (
    NULL,
    NULL,
    NULL,
    NULL,
    '{bcrypt}$2a$10$KUjJZgvBkLEOFiU0C8Xvcud0y2krHaDhqsV6eWELmkOOAvTjlX2h2',
    'user',
    default
  );

insert into
  oauth2.oauth2_authority (authority)
values
  ('ROLE_USER');

insert into
  oauth2.oauth2_users_authorities (users_id, authorities_id)
values
  (
    select
      id
    from
      oauth2.oauth2_user
    where
      oauth2.oauth2_user.username = 'user',
      'ROLE_USER'
  );

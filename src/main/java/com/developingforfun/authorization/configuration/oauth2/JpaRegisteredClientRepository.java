package com.developingforfun.authorization.configuration.oauth2;

import com.developingforfun.authorization.entity.OAuth2ClientEntity;
import com.developingforfun.authorization.repository.OAuth2ClientRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Service
@Primary
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

  private final OAuth2ClientRepository OAuth2ClientRepository;
  private final ObjectMapper objectMapper = new ObjectMapper();

  public JpaRegisteredClientRepository(OAuth2ClientRepository OAuth2ClientRepository) {
    Assert.notNull(OAuth2ClientRepository, "clientRepository cannot be null");
    this.OAuth2ClientRepository = OAuth2ClientRepository;

    ClassLoader classLoader = JpaRegisteredClientRepository.class.getClassLoader();
    List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
    this.objectMapper.registerModules(securityModules);
    this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
  }

  @Override
  public void save(RegisteredClient registeredClient) {
    Assert.notNull(registeredClient, "registeredClient cannot be null");
    this.OAuth2ClientRepository.save(toEntity(registeredClient));
  }

  @Override
  public RegisteredClient findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    return this.OAuth2ClientRepository.findById(id).map(this::toObject).orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    Assert.hasText(clientId, "clientId cannot be empty");
    return this.OAuth2ClientRepository.findByClientId(clientId).map(this::toObject).orElse(null);
  }

  private RegisteredClient toObject(OAuth2ClientEntity OAuth2ClientEntity) {
    Set<String> clientAuthenticationMethods =
        StringUtils.commaDelimitedListToSet(OAuth2ClientEntity.getClientAuthenticationMethods());
    Set<String> authorizationGrantTypes =
        StringUtils.commaDelimitedListToSet(OAuth2ClientEntity.getAuthorizationGrantTypes());
    Set<String> redirectUris =
        StringUtils.commaDelimitedListToSet(OAuth2ClientEntity.getRedirectUris());
    Set<String> clientScopes = StringUtils.commaDelimitedListToSet(OAuth2ClientEntity.getScopes());

    RegisteredClient.Builder builder =
        RegisteredClient.withId(OAuth2ClientEntity.getId())
            .clientId(OAuth2ClientEntity.getClientId())
            .clientIdIssuedAt(OAuth2ClientEntity.getClientIdIssuedAt())
            .clientSecret(OAuth2ClientEntity.getClientSecret())
            .clientSecretExpiresAt(OAuth2ClientEntity.getClientSecretExpiresAt())
            .clientName(OAuth2ClientEntity.getClientName())
            .clientAuthenticationMethods(
                authenticationMethods ->
                    clientAuthenticationMethods.forEach(
                        authenticationMethod ->
                            authenticationMethods.add(
                                resolveClientAuthenticationMethod(authenticationMethod))))
            .authorizationGrantTypes(
                (grantTypes) ->
                    authorizationGrantTypes.forEach(
                        grantType -> grantTypes.add(resolveAuthorizationGrantType(grantType))))
            .redirectUris((uris) -> uris.addAll(redirectUris))
            .scopes((scopes) -> scopes.addAll(clientScopes));

    Map<String, Object> clientSettingsMap = parseMap(OAuth2ClientEntity.getClientSettings());
    builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

    Map<String, Object> tokenSettingsMap = parseMap(OAuth2ClientEntity.getTokenSettings());
    builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

    return builder.build();
  }

  private OAuth2ClientEntity toEntity(RegisteredClient registeredClient) {
    List<String> clientAuthenticationMethods =
        new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
    registeredClient
        .getClientAuthenticationMethods()
        .forEach(
            clientAuthenticationMethod ->
                clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

    List<String> authorizationGrantTypes =
        new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
    registeredClient
        .getAuthorizationGrantTypes()
        .forEach(
            authorizationGrantType ->
                authorizationGrantTypes.add(authorizationGrantType.getValue()));

    OAuth2ClientEntity entity = new OAuth2ClientEntity();
    entity.setId(registeredClient.getId());
    entity.setClientId(registeredClient.getClientId());
    entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
    entity.setClientSecret(registeredClient.getClientSecret());
    entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
    entity.setClientName(registeredClient.getClientName());
    entity.setClientAuthenticationMethods(
        StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
    entity.setAuthorizationGrantTypes(
        StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
    entity.setRedirectUris(
        StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
    entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
    entity.setClientSettings(writeMap(registeredClient.getClientSettings().getSettings()));
    entity.setTokenSettings(writeMap(registeredClient.getTokenSettings().getSettings()));

    return entity;
  }

  private Map<String, Object> parseMap(String data) {
    try {
      return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private String writeMap(Map<String, Object> data) {
    try {
      return this.objectMapper.writeValueAsString(data);
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private static AuthorizationGrantType resolveAuthorizationGrantType(
      String authorizationGrantType) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.AUTHORIZATION_CODE;
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS
        .getValue()
        .equals(authorizationGrantType)) {
      return AuthorizationGrantType.CLIENT_CREDENTIALS;
    } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.REFRESH_TOKEN;
    }
    return new AuthorizationGrantType(authorizationGrantType); // Custom authorization grant type
  }

  private static ClientAuthenticationMethod resolveClientAuthenticationMethod(
      String clientAuthenticationMethod) {
    if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC
        .getValue()
        .equals(clientAuthenticationMethod)) {
      return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
    } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST
        .getValue()
        .equals(clientAuthenticationMethod)) {
      return ClientAuthenticationMethod.CLIENT_SECRET_POST;
    } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
      return ClientAuthenticationMethod.NONE;
    }
    return new ClientAuthenticationMethod(
        clientAuthenticationMethod); // Custom client authentication method
  }
}

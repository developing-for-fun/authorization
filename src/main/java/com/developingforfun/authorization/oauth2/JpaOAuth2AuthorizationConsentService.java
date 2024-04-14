package com.developingforfun.authorization.oauth2;

import com.developingforfun.authorization.entity.OAuth2AuthorizationConsent;
import com.developingforfun.authorization.repository.OAuth2AuthorizationConsentRepository;
import java.util.HashSet;
import java.util.Set;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Service
@Primary
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

  private final OAuth2AuthorizationConsentRepository OAuth2AuthorizationConsentRepository;
  private final RegisteredClientRepository registeredClientRepository;

  public JpaOAuth2AuthorizationConsentService(
      OAuth2AuthorizationConsentRepository OAuth2AuthorizationConsentRepository,
      RegisteredClientRepository registeredClientRepository) {
    Assert.notNull(
        OAuth2AuthorizationConsentRepository, "authorizationConsentRepository cannot be null");
    Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
    this.OAuth2AuthorizationConsentRepository = OAuth2AuthorizationConsentRepository;
    this.registeredClientRepository = registeredClientRepository;
  }

  @Override
  public void save(
      org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
          OAuth2AuthorizationConsent) {
    Assert.notNull(OAuth2AuthorizationConsent, "authorizationConsent cannot be null");
    this.OAuth2AuthorizationConsentRepository.save(toEntity(OAuth2AuthorizationConsent));
  }

  @Override
  public void remove(
      org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
          OAuth2AuthorizationConsent) {
    Assert.notNull(OAuth2AuthorizationConsent, "authorizationConsent cannot be null");
    this.OAuth2AuthorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
        OAuth2AuthorizationConsent.getRegisteredClientId(),
        OAuth2AuthorizationConsent.getPrincipalName());
  }

  @Override
  public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
      findById(String registeredClientId, String principalName) {
    Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
    Assert.hasText(principalName, "principalName cannot be empty");
    return this.OAuth2AuthorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
            registeredClientId, principalName)
        .map(this::toObject)
        .orElse(null);
  }

  private org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
      toObject(OAuth2AuthorizationConsent OAuth2AuthorizationConsent) {
    String registeredClientId = OAuth2AuthorizationConsent.getRegisteredClientId();
    RegisteredClient registeredClient =
        this.registeredClientRepository.findById(registeredClientId);
    if (registeredClient == null) {
      throw new DataRetrievalFailureException(
          "The RegisteredClient with id '"
              + registeredClientId
              + "' was not found in the RegisteredClientRepository.");
    }

    org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent.Builder
        builder =
            org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
                .withId(registeredClientId, OAuth2AuthorizationConsent.getPrincipalName());
    if (OAuth2AuthorizationConsent.getAuthorities() != null) {
      for (String authority :
          StringUtils.commaDelimitedListToSet(OAuth2AuthorizationConsent.getAuthorities())) {
        builder.authority(new SimpleGrantedAuthority(authority));
      }
    }

    return builder.build();
  }

  private OAuth2AuthorizationConsent toEntity(
      org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
          OAuth2AuthorizationConsent) {
    OAuth2AuthorizationConsent entity = new OAuth2AuthorizationConsent();
    entity.setRegisteredClientId(OAuth2AuthorizationConsent.getRegisteredClientId());
    entity.setPrincipalName(OAuth2AuthorizationConsent.getPrincipalName());

    Set<String> authorities = new HashSet<>();
    for (GrantedAuthority authority : OAuth2AuthorizationConsent.getAuthorities()) {
      authorities.add(authority.getAuthority());
    }
    entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

    return entity;
  }
}

package com.developingforfun.authorization.configuration.oauth2;

import com.developingforfun.authorization.entity.OAuth2AuthorizationConsentEntity;
import com.developingforfun.authorization.repository.OAuth2AuthorizationConsentRepository;
import java.util.HashSet;
import java.util.Set;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Primary
@Service
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

  private final OAuth2AuthorizationConsentRepository oAuth2AuthorizationConsentRepository;
  private final RegisteredClientRepository registeredClientRepository;

  public JpaOAuth2AuthorizationConsentService(
      OAuth2AuthorizationConsentRepository OAuth2AuthorizationConsentRepository,
      RegisteredClientRepository registeredClientRepository) {
    Assert.notNull(
        OAuth2AuthorizationConsentRepository, "authorizationConsentRepository cannot be null");
    Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
    oAuth2AuthorizationConsentRepository = OAuth2AuthorizationConsentRepository;
    this.registeredClientRepository = registeredClientRepository;
  }

  @Override
  public void save(OAuth2AuthorizationConsent OAuth2AuthorizationConsent) {
    Assert.notNull(OAuth2AuthorizationConsent, "authorizationConsent cannot be null");
    oAuth2AuthorizationConsentRepository.save(toEntity(OAuth2AuthorizationConsent));
  }

  @Override
  public void remove(OAuth2AuthorizationConsent OAuth2AuthorizationConsent) {
    Assert.notNull(OAuth2AuthorizationConsent, "authorizationConsent cannot be null");
    oAuth2AuthorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
        OAuth2AuthorizationConsent.getRegisteredClientId(),
        OAuth2AuthorizationConsent.getPrincipalName());
  }

  @Override
  public org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
      findById(String registeredClientId, String principalName) {
    Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
    Assert.hasText(principalName, "principalName cannot be empty");
    return oAuth2AuthorizationConsentRepository
        .findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
        .map(this::toObject)
        .orElse(null);
  }

  private org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent
      toObject(OAuth2AuthorizationConsentEntity OAuth2AuthorizationConsentEntity) {
    String registeredClientId = OAuth2AuthorizationConsentEntity.getRegisteredClientId();
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
                .withId(registeredClientId, OAuth2AuthorizationConsentEntity.getPrincipalName());
    if (OAuth2AuthorizationConsentEntity.getAuthorities() != null) {
      for (String authority :
          StringUtils.commaDelimitedListToSet(OAuth2AuthorizationConsentEntity.getAuthorities())) {
        builder.authority(new SimpleGrantedAuthority(authority));
      }
    }

    return builder.build();
  }

  private OAuth2AuthorizationConsentEntity toEntity(
      OAuth2AuthorizationConsent OAuth2AuthorizationConsent) {
    OAuth2AuthorizationConsentEntity entity = new OAuth2AuthorizationConsentEntity();
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

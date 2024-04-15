package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2AuthorizationConsentEntity;
import com.developingforfun.authorization.entity.OAuth2AuthorizationConsentEntity.OAuth2AuthorizationConsentId;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2AuthorizationConsentRepository
    extends JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentId> {

  Optional<OAuth2AuthorizationConsentEntity> findByRegisteredClientIdAndPrincipalName(
      String registeredClientId, String principalName);

  void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}

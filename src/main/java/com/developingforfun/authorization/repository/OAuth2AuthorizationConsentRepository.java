package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2AuthorizationConsent;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2AuthorizationConsentRepository
    extends JpaRepository<
        OAuth2AuthorizationConsent, OAuth2AuthorizationConsent.AuthorizationConsentId> {

  Optional<OAuth2AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(
      String registeredClientId, String principalName);

  void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}

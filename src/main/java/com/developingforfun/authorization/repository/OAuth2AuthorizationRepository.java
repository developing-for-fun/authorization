package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2AuthorizationEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OAuth2AuthorizationRepository
    extends JpaRepository<OAuth2AuthorizationEntity, String> {

  Optional<OAuth2AuthorizationEntity> findByState(String state);

  Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCode);

  Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String accessToken);

  Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshToken);

  @Query(
      "select a from OAuth2AuthorizationEntity a where a.state = :token"
          + " or a.authorizationCodeValue = :token"
          + " or a.accessTokenValue = :token"
          + " or a.refreshTokenValue = :token")
  Optional<OAuth2AuthorizationEntity>
      findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(
          @Param("token") String token);
}

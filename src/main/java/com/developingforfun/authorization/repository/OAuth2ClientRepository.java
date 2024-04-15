package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2ClientEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2ClientEntity, String> {

  Optional<OAuth2ClientEntity> findByClientId(String clientId);
}

package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, String> {

  Optional<OAuth2Client> findByClientId(String clientId);
}

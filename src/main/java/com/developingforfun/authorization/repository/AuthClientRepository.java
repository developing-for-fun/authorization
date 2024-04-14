package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthClientRepository extends JpaRepository<Client, String> {

  Optional<Client> findByClientId(String clientId);
}

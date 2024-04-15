package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2UserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2UserRepository extends JpaRepository<OAuth2UserEntity, Integer> {

  Optional<OAuth2UserEntity> findByUsername(String username);

  void deleteByUsername(String username);
}

package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.OAuth2User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2UserRepository extends JpaRepository<OAuth2User, Integer> {

  OAuth2User findByUsername(String username);
}

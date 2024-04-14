package com.developingforfun.authorization.repository;

import com.developingforfun.authorization.entity.SecurityUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthUserRepository extends JpaRepository<SecurityUser, Integer> {

  SecurityUser findByUsername(String username);
}

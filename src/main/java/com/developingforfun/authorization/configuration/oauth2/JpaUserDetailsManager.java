package com.developingforfun.authorization.configuration.oauth2;

import com.developingforfun.authorization.entity.OAuth2AuthorityEntity;
import com.developingforfun.authorization.entity.OAuth2UserEntity;
import com.developingforfun.authorization.repository.OAuth2UserRepository;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Primary
@Service
@RequiredArgsConstructor
@Slf4j
public class JpaUserDetailsManager implements UserDetailsManager {

  private final OAuth2UserRepository oAuth2UserRepository;

  private AuthenticationManager authenticationManager;

  private SecurityContextHolderStrategy securityContextHolderStrategy =
      SecurityContextHolder.getContextHolderStrategy();

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Optional<OAuth2UserEntity> optionalOAuth2UserEntity =
        oAuth2UserRepository.findByUsername(username);
    if (optionalOAuth2UserEntity.isEmpty()) {
      throw new UsernameNotFoundException(username);
    }

    OAuth2UserEntity oAuth2UserEntity = optionalOAuth2UserEntity.get();
    Collection<GrantedAuthority> authorities = new HashSet<>();
    oAuth2UserEntity
        .getAuthorities()
        .forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getAuthority())));

    return new User(
        oAuth2UserEntity.getUsername(),
        oAuth2UserEntity.getPassword(),
        oAuth2UserEntity.getEnabled(),
        oAuth2UserEntity.getAccountNonExpired(),
        oAuth2UserEntity.getCredentialsNonExpired(),
        oAuth2UserEntity.getAccountNonLocked(),
        authorities);
  }

  @Override
  public void createUser(UserDetails user) {
    Optional<OAuth2UserEntity> optionalOAuth2UserEntity =
        oAuth2UserRepository.findByUsername(user.getUsername());
    Assert.isTrue(optionalOAuth2UserEntity.isEmpty(), "user should not exist");

    OAuth2UserEntity oAuth2UserEntity = new OAuth2UserEntity();
    copyUser(user, oAuth2UserEntity);
    oAuth2UserRepository.save(oAuth2UserEntity);
  }

  @Override
  public void updateUser(UserDetails user) {
    Optional<OAuth2UserEntity> optionalOAuth2UserEntity =
        oAuth2UserRepository.findByUsername(user.getUsername());
    Assert.isTrue(optionalOAuth2UserEntity.isPresent(), "user should exist");

    OAuth2UserEntity oAuth2UserEntity = optionalOAuth2UserEntity.get();
    copyUser(user, oAuth2UserEntity);
    oAuth2UserRepository.save(oAuth2UserEntity);
  }

  @Override
  public void deleteUser(String username) {
    oAuth2UserRepository.deleteByUsername(username);
  }

  @Override
  public void changePassword(String oldPassword, String newPassword) {
    Authentication currentUser =
        this.securityContextHolderStrategy.getContext().getAuthentication();
    if (currentUser == null) {
      throw new AccessDeniedException(
          "Can't change password as no Authentication object found in context for current user.");
    } else {
      String username = currentUser.getName();
      log.debug("Changing password for user {}", username);
      if (this.authenticationManager != null) {
        log.debug("Re-authenticating user {} for password change request.", username);
        this.authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken.unauthenticated(username, oldPassword));
      } else {
        log.debug("No authentication manager set. Password won't be re-checked.");
      }

      Optional<OAuth2UserEntity> optionalOAuth2UserEntity =
          oAuth2UserRepository.findByUsername(username);
      Assert.state(optionalOAuth2UserEntity.isPresent(), "Current user doesn't exist in database.");
      OAuth2UserEntity oAuth2UserEntity = optionalOAuth2UserEntity.get();
      oAuth2UserEntity.setPassword(newPassword);
      oAuth2UserRepository.save(oAuth2UserEntity);
    }
  }

  @Override
  public boolean userExists(String username) {
    Optional<OAuth2UserEntity> optionalOAuth2UserEntity =
        oAuth2UserRepository.findByUsername(username);
    return optionalOAuth2UserEntity.isPresent()
        && optionalOAuth2UserEntity.get().getUsername().equals(username);
  }

  public void copyUser(UserDetails user, OAuth2UserEntity oAuth2UserEntity) {
    oAuth2UserEntity.setPassword(user.getPassword());
    oAuth2UserEntity.setUsername(user.getUsername());

    Set<OAuth2AuthorityEntity> authorities = new HashSet<>();
    user.getAuthorities()
        .forEach(
            grantedAuthority -> {
              OAuth2AuthorityEntity oAuth2AuthorityEntity = new OAuth2AuthorityEntity();
              oAuth2AuthorityEntity.setAuthority(grantedAuthority.getAuthority());
              authorities.add(oAuth2AuthorityEntity);
            });
    oAuth2UserEntity.setAuthorities(authorities);
  }
}

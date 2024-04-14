package com.developingforfun.authorization.oauth2;

import com.developingforfun.authorization.entity.OAuth2User;
import com.developingforfun.authorization.repository.OAuth2UserRepository;
import java.util.Collection;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@Primary
public class JpaUserDetailsManager implements UserDetailsManager {

  private final OAuth2UserRepository OAuth2UserRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    OAuth2User user = OAuth2UserRepository.findByUsername(username);
    if (!user.getUsername().equals(username)) {
      throw new UsernameNotFoundException("Access Denied");
    }
    Collection<GrantedAuthority> authorities = new HashSet<>();
    user.getAuthorities()
        .forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getAuthority())));
    return new User(
        user.getUsername(),
        user.getPassword(),
        user.getEnabled(),
        user.getAccountNonExpired(),
        user.getCredentialsNonExpired(),
        user.getAccountNonLocked(),
        authorities);
  }

  @Override
  public void createUser(UserDetails user) {}

  @Override
  public void updateUser(UserDetails user) {}

  @Override
  public void deleteUser(String username) {}

  @Override
  public void changePassword(String oldPassword, String newPassword) {}

  @Override
  public boolean userExists(String username) {
    OAuth2User user = OAuth2UserRepository.findByUsername(username);
    if (user.getUsername().equals(username)) {
      return true;
    }
    return false;
  }
}

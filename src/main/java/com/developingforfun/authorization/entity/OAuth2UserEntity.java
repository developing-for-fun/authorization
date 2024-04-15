package com.developingforfun.authorization.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Entity
@Table(name = "oauth2_user")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2UserEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  @NonNull
  @Column(unique = true)
  private String username;

  @NonNull private String password;

  @ManyToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  @JoinTable(
      name = "oauth2_users_authorities",
      joinColumns = {@JoinColumn(name = "USERS_ID", referencedColumnName = "ID")},
      inverseJoinColumns = {
        @JoinColumn(name = "AUTHORITIES_ID", referencedColumnName = "AUTHORITY")
      })
  private Set<OAuth2AuthorityEntity> authorities;

  private Boolean accountNonExpired;
  private Boolean accountNonLocked;
  private Boolean credentialsNonExpired;
  private Boolean enabled;
}

package com.developingforfun.authorization.entity;

import com.developingforfun.authorization.enums.PermissionEnum;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "oauth2_client")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2ClientEntity {

  @Id private String id;
  private String clientId;
  private Instant clientIdIssuedAt;
  private String clientSecret;
  private Instant clientSecretExpiresAt;
  private String clientName;

  @Column(length = 1000)
  private String clientAuthenticationMethods;

  @Column(length = 1000)
  private String authorizationGrantTypes;

  @Column(length = 1000)
  private String redirectUris;

  @Column(length = 1000)
  private String scopes;

  @Column(length = 2000)
  private String clientSettings;

  @Column(length = 2000)
  private String tokenSettings;

  @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
  private Set<OAuth2PermissionEntity> permissions;

  @Transient
  public List<PermissionEnum> getPermissionList() {
    return permissions.stream()
        .map(OAuth2PermissionEntity::getPermission)
        .collect(Collectors.toList());
  }
}

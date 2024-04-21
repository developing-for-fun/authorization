package com.developingforfun.authorization.entity;

import com.developingforfun.authorization.enums.PermissionEnum;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "oauth2_permission")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2PermissionEntity {

  @Id
  @Enumerated(EnumType.STRING)
  private PermissionEnum permission;
}

package com.developingforfun.authorization.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "oauth2_authority")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2AuthorityEntity {

  @Id private String authority;
}

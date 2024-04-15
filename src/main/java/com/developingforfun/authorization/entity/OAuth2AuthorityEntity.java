package com.developingforfun.authorization.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_authority")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2AuthorityEntity {

  @Id private String authority;
}

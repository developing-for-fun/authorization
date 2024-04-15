package com.developingforfun.authorization.entity;

import com.developingforfun.authorization.entity.OAuth2AuthorizationConsentEntity.OAuth2AuthorizationConsentId;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "oauth2_authorization_consent")
@IdClass(OAuth2AuthorizationConsentId.class)
@Data
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2AuthorizationConsentEntity {

  @Id private String registeredClientId;
  @Id private String principalName;

  @Column(length = 1000)
  private String authorities;

  public static class OAuth2AuthorizationConsentId implements Serializable {

    private static final long serialVersionUID = 1L;
    private String registeredClientId;
    private String principalName;

    public String getRegisteredClientId() {
      return registeredClientId;
    }

    public void setRegisteredClientId(String registeredClientId) {
      this.registeredClientId = registeredClientId;
    }

    public String getPrincipalName() {
      return principalName;
    }

    public void setPrincipalName(String principalName) {
      this.principalName = principalName;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      OAuth2AuthorizationConsentId that = (OAuth2AuthorizationConsentId) o;
      return registeredClientId.equals(that.registeredClientId)
          && principalName.equals(that.principalName);
    }

    @Override
    public int hashCode() {
      return Objects.hash(registeredClientId, principalName);
    }
  }
}

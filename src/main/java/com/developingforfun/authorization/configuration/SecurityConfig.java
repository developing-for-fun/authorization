package com.developingforfun.authorization.configuration;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;
import static org.springframework.security.config.Customizer.withDefaults;

import com.developingforfun.authorization.entity.OAuth2ClientEntity;
import com.developingforfun.authorization.repository.OAuth2ClientRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private static final String[] AUTH_WHITELIST = {
    // Actuators
    "/actuator/**", "/health/**", "/management/**",
  };

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    /*
     * -----------------
     * Default Endpoints
     * -----------------
     *
     * Authorization Endpoint           /oauth2/authorize
     * Token Endpoint                   /oauth2/token
     * Token Revocation                 /oauth2/revoke
     * Token Introspection              /oauth2/introspect
     * JWK Set Endpoint                 /oauth2/jwks
     * Authorization Server Metadata    /.well-known/oauth-authorization-server
     * OIDC Provider Configuration      /.well-known/openid-configuration
     */
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        .oidc(withDefaults()); // Enable OpenID Connect 1.0

    http.cors(
        httpSecurityCorsConfigurer ->
            httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()));

    http
        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        .exceptionHandling(
            (exceptions) ->
                exceptions.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
        // Accept access tokens for User Info and/or Client Registration
        .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http
        // disable frame options for h2-console
        .headers((headers) -> headers.frameOptions(FrameOptionsConfig::disable))
        // disable csrf for h2-console
        .csrf(csrf -> csrf.ignoringRequestMatchers(toH2Console()).disable())
        .authorizeHttpRequests(
            (authorize) ->
                authorize
                    .requestMatchers(AUTH_WHITELIST)
                    .permitAll()
                    .requestMatchers(toH2Console())
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        .formLogin(withDefaults());

    return http.build();
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(
      OAuth2ClientRepository oAuth2ClientRepository) {
    return (context) -> {
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        context
            .getClaims()
            .claims(
                (claims) -> {
                  Optional<OAuth2ClientEntity> optionalOAuth2ClientEntity =
                      oAuth2ClientRepository.findByClientId(
                          context.getRegisteredClient().getClientId());
                  if (optionalOAuth2ClientEntity.isPresent()) {
                    OAuth2ClientEntity oAuth2ClientEntity = optionalOAuth2ClientEntity.get();
                    claims.put("per", oAuth2ClientEntity.getPermissionList());
                  }
                });
      }
    };
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedMethods(
        List.of(
            HttpMethod.GET.name(),
            HttpMethod.PUT.name(),
            HttpMethod.POST.name(),
            HttpMethod.DELETE.name(),
            HttpMethod.OPTIONS.name(),
            HttpMethod.PATCH.name()));

    configuration.setAllowedHeaders(
        List.of(
            "Content-Type, api_key, "
                + "X-Requested-With, "
                + "Authorization, "
                + "DNT,X-CustomHeader,"
                + "Keep-Alive,User-Agent,"
                + "X-Requested-With,"
                + "If-Modified-Since,"
                + "Cache-Control,"
                + "Content-Type,"
                + "Content-Range,Range"));

    configuration.setAllowedOrigins(List.of("*"));
    configuration.setAllowCredentials(true);
    configuration.addExposedHeader("Authorization");
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration.applyPermitDefaultValues());

    return source;
  }
}

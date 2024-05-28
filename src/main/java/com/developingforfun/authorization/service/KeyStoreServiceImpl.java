package com.developingforfun.authorization.service;

import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

@Service
public class KeyStoreServiceImpl implements KeyStoreService {
  @Value("${security.jwt.keystore-file:null}")
  String keystoreFile;

  @Value("${security.jwt.alias:null}")
  String alias;

  @Value("${security.jwt.keystore-password:null}")
  String keystorePassword;

  @Override
  public RSAKey generateRSAKey() {
    KeyPair keyPair = getKeyPairFromFile();

    // For local PoC; else throw error
    if (keyPair == null) {

      keyPair = generateRandomKeyPair();
    }

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
  }

  private KeyPair getKeyPairFromFile() {
    KeyPair keyPair;

    try {
      var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      keyStore.load(
          new ClassPathResource(keystoreFile).getInputStream(), keystorePassword.toCharArray());

      var privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());

      Certificate certificate = keyStore.getCertificate(alias);
      PublicKey publicKey = certificate.getPublicKey();

      keyPair = new KeyPair(publicKey, privateKey);
    } catch (KeyStoreException
        | IOException
        | NoSuchAlgorithmException
        | CertificateException
        | UnrecoverableKeyException e) {
      return null;
    }

    return keyPair;
  }

  private static KeyPair generateRandomKeyPair() {
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
}

package com.developingforfun.authorization.service;

import com.nimbusds.jose.jwk.RSAKey;

public interface KeyStoreService {
  RSAKey generateRSAKey();
}

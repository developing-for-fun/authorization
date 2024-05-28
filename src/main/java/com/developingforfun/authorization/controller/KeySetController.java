package com.developingforfun.authorization.controller;

import com.developingforfun.authorization.service.KeyStoreService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class KeySetController {

  private final KeyStoreService keyStoreService;

  public KeySetController(KeyStoreService keyStoreService) {
    this.keyStoreService = keyStoreService;
  }

  @GetMapping("/oauth/keysets")
  public String getKeySet() {
    return keyStoreService.generateRSAKey().toJSONString();
  }
}

package com.thejackfolio.microservices.apigateway.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "IDENTITY-SERVICE")
public interface IdentityClient {

    @GetMapping("/identity/validate")
    public ResponseEntity<Boolean> validateToken(@RequestParam("token") String token);
}

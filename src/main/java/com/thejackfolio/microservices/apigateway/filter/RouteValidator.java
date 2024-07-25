package com.thejackfolio.microservices.apigateway.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
            "/identity/register",
            "/identity/token",
            "/details/get-details",
            "/skills/get-skills",
            "/comments/save-comments",
            "/comments/get-comments",
            "/credential/save-credential",
            "/credential/get-credential",
            "/joiners/save-joiner",
            "/eureka"
    );

    public Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoints
                    .stream()
                    .noneMatch(uri -> request.getURI().getPath().contains(uri));
}

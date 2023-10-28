package com.thejackfolio.microservices.apigateway.filter;

import com.thejackfolio.microservices.apigateway.utilities.JwtUtil;
import com.thejackfolio.microservices.apigateway.utilities.StringConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Autowired
    private RouteValidator validator;
    @Autowired
    private JwtUtil jwtUtil;
//    @Autowired
//    private IdentityClient client;
    @Autowired
    private RestTemplate template;

    public static class Config {}

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException(StringConstants.HEADER_NOT_FOUND);
                }
                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith(StringConstants.BEARER)) {
                    authHeader = authHeader.substring(7);
                }
//                ResponseEntity<Boolean> response = client.validateToken(authHeader);
//                boolean responseBody = response.getBody();
//                if(!responseBody){
//                    LOGGER.error(StringConstants.UNAUTHORIZED_ACCESS);
//                    throw new RuntimeException(StringConstants.UNAUTHORIZED_ACCESS);
//                }
                try {
                    jwtUtil.validateToken(authHeader);
                } catch (Exception e) {
                    LOGGER.error(StringConstants.UNAUTHORIZED_ACCESS);
                    throw new RuntimeException(StringConstants.UNAUTHORIZED_ACCESS);
                }
            }
            return chain.filter(exchange);
        });
    }
}

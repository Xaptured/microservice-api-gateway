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

import java.util.List;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Autowired
    private RouteValidator validator;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private RestTemplate template;

    public static class Config {
        private String role;

        public Config() {
        }

        public Config(String role) {
            this.role = role;
        }

        public String getRole() {
            return role;
        }

        public void setRole(String role) {
            this.role = role;
        }
    }

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
                try {
                    jwtUtil.validateToken(authHeader);
                    List<String> rolesFromToken = jwtUtil.getRolesFromToken(authHeader);
                    String role = rolesFromToken.get(0);
                    if(!role.equals(config.getRole())){
                        throw new RuntimeException(StringConstants.UNAUTHORIZED_ACCESS);
                    }
                } catch (Exception exception) {
                    LOGGER.error(StringConstants.UNAUTHORIZED_ACCESS);
                    throw new RuntimeException(StringConstants.UNAUTHORIZED_ACCESS);
                }
            }
            return chain.filter(exchange);
        });
    }
}

package com.thejackfolio.microservices.apigateway.configurations;

import com.thejackfolio.microservices.apigateway.utilities.PropertiesReader;
import com.thejackfolio.microservices.apigateway.utilities.StringConstants;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.client.RestTemplate;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {


    private static final String USERNAME = PropertiesReader.getProperty(StringConstants.USERNAME);
    private static final String PASSWORD = PropertiesReader.getProperty(StringConstants.PASSWORD);
    private static final String ROLE = PropertiesReader.getProperty(StringConstants.ROLE);
    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails adminUser = User.withUsername(USERNAME)
                .password(PASSWORD)
                .roles(ROLE)
                .build();
        return new MapReactiveUserDetailsService(adminUser);
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.formLogin().and().authorizeExchange()
                .pathMatchers("/actuator/**").hasRole(ROLE).anyExchange().permitAll()
                .and()
                .logout().and().csrf().disable().httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public RestTemplate template(){
        return new RestTemplate();
    }
}

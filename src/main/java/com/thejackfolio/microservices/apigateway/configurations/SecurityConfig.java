package com.thejackfolio.microservices.apigateway.configurations;

import com.thejackfolio.microservices.apigateway.utilities.PropertiesReader;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {


    private static final String USERNAME = PropertiesReader.getProperty("USERNAME");
    private static final String PASSWORD = PropertiesReader.getProperty("PASSWORD");
    private static final String ROLE = PropertiesReader.getProperty("ROLE");
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
}

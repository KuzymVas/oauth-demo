package com.example.oauthdemo.configurations;

import com.example.oauthdemo.security.AuthoritiesFromUsernameConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


    /**
     * Security chain for HTTP Basic authentication via REST request (no form)
     * Checks for match first (due to @Order) and only matches for /api/login endpoint
     * Lets through any authenticated user
     */
    @Bean
    @Order(1)
    public SecurityFilterChain httpBasicSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/login")
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    /**
     * Security chain for access without authentication
     * Checks for match second (due to @Order) and matches all endpoints under /unsecured/**
     * Lets through everyone (but still logs access and can run custom filters, for monitoring, etc as parts of this chain)
     */
    @Bean
    @Order(2)
    public SecurityFilterChain permitAllSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/unsecured/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    /**
     * Security chain for access via JWT
     * Checks for match third (due to @Order) and matches all endpoints under /api/** (except those, that were already matched before, obviously)
     * Lets through users based on their ROLE and HTTP request type and endpoint
     */
    @Bean
    @Order(3)
    public SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder, JwtAuthenticationConverter converter) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST).hasRole("ADMIN")
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().hasRole("USER"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder)
                                .jwtAuthenticationConverter(converter)
                        )
                );
        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter converter(AuthoritiesFromUsernameConverter authoritiesFromUsernameConverter) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesFromUsernameConverter);
        return jwtAuthenticationConverter;
    }

}

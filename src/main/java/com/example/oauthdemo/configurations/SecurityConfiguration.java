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

/**
 *  Here all security filter chains are configured.
 *
 *  Note, that CSRF protection is disabled to allow for easier flow with Postman.
 *  While it is often disabled in backend-to-backend communication, it should not be done so, when frontend is involved
 *  and real CSRF attack happens.
 *
 *  Please, do not use this as example, if CSRF attacks are part of your threat model.
 *
 */
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
     * Security chain for OAuth 2 authentication.
     * Checks for match second (due to @Order) and only matches for /api/github/login endpoint
     * Due to internal redirects it should also match for /oauth2/** and /login/oauth2/code/** endpoints.
     * If it would not, OAuth Flow would be broken after redirect to those endpoints.
     * The flow goes similar to this (please use actual OAuth 2 documentation for more details):
     * 1) Client does GET /api/github/login Spring Security checks, if Github login was already complete (it asks Github on this step). If not, it redirects to /oauth2/authorize
     * 2) Client does GET /oauth2/authorize IF same filter chain is invoked, Spring Security redirects to Github login page ( and adds your clientId in this step, so Github knows, which app is doing the flow).
     * 3) After login is complete Github redirects to your redirect URL (by default /login/oauth2/code/... )
     * 4) Client does GET /login/oauth2/code/... passing in values from Github to finish authorization (those values are matched with your client secret, so only your app would be able to use them). IF same filter chain is invoked, Spring Security accepts them, confirms them with Github, and redirects you back to original page.
     * 5) Client does GET  /api/github/login?continue and Spring Security let it through with Github authorization in place.
     *
     * On step 2) and 4) if those redirected GET requests do not hit the same security filter chain (this one), our flow would be interrupted and we would get/error page
     *
     * Lets through any authenticated user
     */
    @Bean
    @Order(2)
    public SecurityFilterChain githubOAuth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/github/login", "/oauth2/**", "/login/oauth2/code/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated()
                )
                .oauth2Login(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Security chain for access without authentication
     * Checks for match third (due to @Order) and matches all endpoints under /unsecured/**
     * Lets through everyone (but still logs access and can run custom filters, for monitoring, etc as parts of this chain)
     */
    @Bean
    @Order(3)
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
     * Checks for match fourth (due to @Order) and matches all endpoints under /api/** (except those, that were already matched before, obviously)
     * Lets through users based on their ROLE and HTTP request type and endpoint
     *
     * Uses Spring Security resource server approach, customized with JWT decoder and converter.
     * It is possible to build JWT authN/authZ logic yourself, since converter and decoder already do most of the job
     * and avoid depending on resource server, but that approach is not covered by this demo.
     *
     */
    @Bean
    @Order(4)
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

    /**
     * Converter bean from JWT to Spring Security authentication object
     * @param authoritiesFromUsernameConverter previously defined JWT to Authorities converter
     */
    @Bean
    public JwtAuthenticationConverter converter(AuthoritiesFromUsernameConverter authoritiesFromUsernameConverter) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesFromUsernameConverter);
        return jwtAuthenticationConverter;
    }

}

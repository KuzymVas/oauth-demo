package com.example.oauthdemo.security;

import com.example.oauthdemo.services.GithubUserService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * This class allows to convert JWT contents into the internally usable Authorities. You would need to implement
 * similar class, if you JWT structure differs from Spring Security default one.
 *
 * In general there are two main ways to link authorities with JWT:
 * - Explicit: when authorities is stored inside JWT as a claim.
 * - Implicit: when application looks up authorities in other way after authenticating user with JWT. (This is one step away from JWT towards opaque token)
 *
 * Choice of approach depends on many factors, for example who determines the authorities: issuer of JWT or its consumer?
 *  (i. e. github can issue token, which gives authority to edit repos in github itself.
 *  OR github can issue token, just confirming your username, and then in your app, which github does not even know about, in DB there is a link between your username and your admin status)
 *
 * This service implements implicit approach, by getting authorities from user detail services, using authenticated username from JWT
 */
@Component
public class AuthoritiesFromUsernameConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final UserDetailsService userDetailsService;
    private final GithubUserService githubUserService;

    public AuthoritiesFromUsernameConverter(UserDetailsService userDetailsService,
                                            GithubUserService githubUserService) {
        this.userDetailsService = userDetailsService;
        this.githubUserService = githubUserService;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        String username = source.getSubject();
        if (githubUserService.isGithubUser(username)) {
            return githubUserService.getGithubUserAuthorities();
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return userDetails.getAuthorities().stream()
                .map(GrantedAuthority.class::cast)
                .toList();
    }
}

package com.example.oauthdemo.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

/**
 * This service is minimalistic of user management for Github authenticated users.
 * All of them would share a single internal account with same username and roles
 * This service is not in focus of the demo, contains multiple shortcuts and vulnerabilities and should not be used as example
 */
@Service
public class GithubUserService {

    // Share username
    private static final String GITHUB_USERNAME = "github_user";

    // Would be assigned to all Github-authenticated users, no matter what github account do they use
    public String getDefaultGithubUsername() { return GITHUB_USERNAME; }

    // Confirms, that user has shared username (on JWT authentication step)
    public boolean isGithubUser(String username) { return GITHUB_USERNAME.equals(username);}

    // Provides role for shared user account
    public Collection<GrantedAuthority> getGithubUserAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }
}
